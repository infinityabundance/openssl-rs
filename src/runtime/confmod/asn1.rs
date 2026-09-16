//! Phase 6.10d — `crypto/asn1/asn_moid.c`: the `oid_section` configuration module.
//!
//! One export, `ASN1_add_oid_module`, and it is four lines: it registers `oid_section` with the
//! module registry, so that a configuration file with
//!
//! ```text
//! openssl_conf = openssl_init
//! [openssl_init]
//! oid_section = new_oids
//! [new_oids]
//! 1.2.3.4 = short_name
//! ```
//!
//! creates an object identifier at `CONF_modules_load` time. That is the whole mechanism:
//! `openssl.cnf` is a place where a *consumer* can name an OID it wants, and this is the one
//! built-in module whose job is to make that possible.
//!
//! ## `do_create` is where the grammar is, and it has three shapes
//!
//! `do_create(value, name)` takes the entry's value and its key. The value may be a bare OID, or
//! `long_name, oid`:
//!
//! | value | long name | OID |
//! |---|---|---|
//! | `1.2.3.4` | the entry's **name** | the whole value |
//! | `, 1.2.3.4` | the entry's name | everything after the leading comma |
//! | `long_name, 1.2.3.4` | the value's head, trimmed | everything after the last comma, trimmed |
//!
//! The third shape carries the traps, and all of them are reachable from a configuration file a
//! person writes by hand. The split is on the **last** comma, so a long name containing one is
//! split there rather than at its first. Trimming is `ossl_isspace` on both ends of the long
//! name and on the OID's *leading* end only. An OID half that is empty after a non-leading comma
//! is a **failure** (`return 0`), while a leading comma with nothing after it is not
//! special-cased at all and reaches `OBJ_create` with an empty string, which `OBJ_txt2obj`
//! then rejects. And the trailing walk
//! `p--; while (isspace(*p)) { if (p == ln) return 0; p--; }` steps backwards over whitespace
//! with a **floor**: a long name that is entirely whitespace fails rather than running off the
//! front of the buffer.
//!
//! ## `NID_undef` is the sentinel in both directions, and that is the surprising part
//!
//! `do_create` answers "created" as `nid != NID_undef`, and `OBJ_create` answers `NID_undef`
//! when **the short or long name is already present** *and* when the OID already is — in both
//! cases after raising `OBJ_R_OID_EXISTS`. So a configuration that re-declares an OID the
//! library already knows does **not** succeed here; the module's initialiser answers 0 and
//! `CONF_modules_load` reports a failure. Read from
//! `crypto/objects/obj_dat.c` rather than inferred, because the opposite assumption is the
//! natural one: "the object exists" and "the object was created" both leave the OID resolvable,
//! and only one of them is what this function answers.
//!
//! ## The finish function is empty, and it is still passed
//!
//! `oid_module_finish` is `{}` in the authority. It is handed to `CONF_module_add` anyway. The
//! difference between passing it and passing NULL is nil where the registry calls it —
//! `module_init`'s `err` arm and `CONF_modules_unload` both check for NULL and then call, so an
//! empty function and a NULL pointer take the same branch — and the registry's `CONF_MODULE` is
//! opaque, so no consumer can tell either. It is transcribed rather than dropped because
//! "the empty function could have been a NULL" is exactly the kind of reasoning that turns out
//! to be wrong somewhere the reader did not look.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::conf::lib::NCONF_get_section;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::confmod::{CONF_module_add, ConfFinishFn, ConfImodule, ConfInitFn};
use crate::runtime::ctype::ossl_isspace;
use crate::runtime::err::err_sites::{ASN_MOID_32, ASN_MOID_38};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::OBJ_create;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

/// `#define NID_undef 0` — `openssl/objects.h`.
///
/// Declared here rather than imported because the crate keeps its own copy private to
/// `src/runtime/obj.rs` (as `obj_table.rs`'s generated constant, re-exported only inside that
/// module). The authority's is a `#define` of zero, and `do_create` compares against it, so the
/// name and the value are the contract rather than an implementation detail of this file.
#[allow(non_upper_case_globals)] // the authority's own spelling, `#define NID_undef 0`
const NID_undef: c_int = 0;

/// `crypto/asn1/asn_moid.c`, for the coordinates of the one allocation this module makes.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/asn1/asn_moid.c".as_ptr();

/// `lntmp = OPENSSL_malloc((p - ln) + 1)` in `do_create`.
const L_LNTMP: c_int = 90;

/// The last comma in `value`, or NULL — `strrchr(value, ',')`.
///
/// # Safety
/// `value` must be NUL-terminated.
unsafe fn last_comma_of(value: *const c_char) -> *const c_char {
    let mut last: *const c_char = ptr::null();
    let mut p = value;
    loop {
        // SAFETY: `value` is NUL-terminated, so this walks a bounded region.
        let c = unsafe { *p };
        if c == 0 {
            return last;
        }
        if c == b',' as c_char {
            last = p;
        }
        // SAFETY: `p` is inside the NUL-terminated `value` and has not yet reached its
        // terminator, so the byte after it is inside the same allocation.
        p = unsafe { p.add(1) };
    }
}

/// `static int do_create(const char *value, const char *name)`.
///
/// Splits one `oid_section` entry into an OID and a long name and creates the object. See the
/// module documentation for the three shapes and the four edge cases.
///
/// # Safety
/// `value` and `name` must be NUL-terminated, and `name` non-NULL — the authority passes the
/// `CONF_VALUE`'s key, which a section entry always has.
unsafe fn do_create(value: *const c_char, name: *const c_char) -> bool {
    // SAFETY: `value` is NUL-terminated per the contract, so the scan is bounded.
    let last_comma = unsafe { last_comma_of(value) };

    // The long name and the OID, plus the buffer to release afterwards if one was allocated.
    let (ln, ostr, owned): (*const c_char, *const c_char, *mut c_char) = if last_comma.is_null() {
        // No comma at all: the long name is the entry's name and the whole value is the OID.
        (name, value, ptr::null_mut())
    } else if last_comma == value {
        // A *leading* comma: the long name is still the entry's name, and the OID is what
        // follows. An empty remainder is deliberately not tested for here; it reaches
        // `OBJ_txt2obj` through `OBJ_create`, which refuses it.
        // SAFETY: `last_comma` points inside `value`.
        (name, unsafe { last_comma.add(1) }, ptr::null_mut())
    } else {
        // `long_name, oid`. The OID half is trimmed from its front only.
        // SAFETY: `last_comma` points inside `value`.
        let mut ostr = unsafe { last_comma.add(1) };
        // SAFETY: `ostr` is within `value` and NUL-terminated.
        if unsafe { *ostr } == 0 {
            return false;
        }
        // SAFETY: as above.
        while unsafe { ossl_isspace(*ostr as c_int) } {
            // SAFETY: `ostr` has not reached the terminator, because `ossl_isspace(0)` is false
            // and the loop would have stopped.
            ostr = unsafe { ostr.add(1) };
        }
        let mut ln = value;
        // SAFETY: as above.
        while unsafe { ossl_isspace(*ln as c_int) } {
            // SAFETY: as for `ostr`: the byte read is not the terminator.
            ln = unsafe { ln.add(1) };
        }
        // The trailing walk, with the authority's floor: `p` starts one before the comma and
        // steps back over whitespace, refusing rather than running past `ln`.
        // SAFETY: the branch is taken only when `last_comma != value`, so `last_comma` is at
        // least `value + 1` and `last_comma - 1` is inside the allocation.
        let mut p = unsafe { last_comma.sub(1) };
        loop {
            // SAFETY: `p` is at or after `ln`, both inside `value`.
            if !unsafe { ossl_isspace(*p as c_int) } {
                break;
            }
            if p == ln {
                return false;
            }
            // SAFETY: `p != ln`, and `ln >= value`, so `p - 1 >= value` — inside the
            // allocation, which the `p == ln` test above is what guarantees.
            p = unsafe { p.sub(1) };
        }
        // SAFETY: the loop broke on a byte that is not whitespace, so `p` is inside the
        // allocation and the byte after it is too — or it is the terminator, which is also a
        // byte of the allocation.
        p = unsafe { p.add(1) };

        // `lntmp = OPENSSL_malloc((p - ln) + 1)`, then the copy and the terminator.
        // SAFETY: `p >= ln` and both are inside `value`.
        let len = unsafe { p.offset_from(ln) } as usize;
        let lntmp = CRYPTO_malloc(len + 1, FILE, L_LNTMP).cast::<c_char>();
        if lntmp.is_null() {
            return false;
        }
        // SAFETY: `lntmp` has room for `len` bytes and a terminator, and `ln` has at least that
        // many readable bytes — the span was measured inside `value`.
        unsafe {
            ptr::copy_nonoverlapping(ln, lntmp, len);
            *lntmp.add(len) = 0;
        }
        (lntmp, ostr, lntmp)
    };

    // SAFETY: `ostr`, `name` and `ln` are NUL-terminated. `OBJ_create` copies every one of them
    // before returning, which is what makes the `CRYPTO_free` on the next line correct.
    let nid = unsafe { OBJ_create(ostr, name, ln) };
    // SAFETY: `owned` is NULL or this function's own allocation; `CRYPTO_free` accepts NULL.
    unsafe { CRYPTO_free(owned.cast(), FILE, L_LNTMP) };

    nid != NID_undef
}

/// `static void oid_module_finish(CONF_IMODULE *md)` — empty, and deliberately still passed.
unsafe extern "C" fn oid_module_finish(_md: *mut ConfImodule) {
    // The authority's body is `{}`: an OID section needs no teardown, because the objects it
    // created belong to the object database and `OBJ_cleanup` is that database's own business.
}

/// `static int oid_module_init(CONF_IMODULE *md, const CONF *cnf)`.
///
/// Reads the section the registry entry names and creates one object per entry. Two failures are
/// raised rather than skipped silently: a section that does not exist, and any single OID that
/// could not be created.
///
/// # Safety
/// `md` must be a live initialisation and `cnf` the configuration it was loaded from.
unsafe extern "C" fn oid_module_init(md: *mut ConfImodule, cnf: *const Conf) -> c_int {
    // SAFETY: `md` is live per the callback's contract. Its value is the section name the
    // configuration gave for `oid_section`.
    let oid_section = unsafe { crate::runtime::confmod::CONF_imodule_get_value(md) };
    // SAFETY: `cnf` is live and `oid_section` is a NUL-terminated string owned by `md`.
    let sktmp = unsafe { NCONF_get_section(cnf, oid_section) };
    if sktmp.is_null() {
        // SAFETY: a compile-time-constant site and this thread's own error queue.
        unsafe { raise_site(&ASN_MOID_32) };
        return 0;
    }

    // SAFETY: `sktmp` is the section's own stack, live for the duration of this call.
    let count = unsafe { OPENSSL_sk_num(sktmp) };
    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`, so this is one of the section's own entries.
        let oval = unsafe { OPENSSL_sk_value(sktmp, i) }.cast::<ConfValue>();
        // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated strings owned by the
        // `CONF`, and the authority passes them in the order `do_create(value, name)`.
        let (value, name) = unsafe { ((*oval).value, (*oval).name) };
        // SAFETY: both are NUL-terminated, and `name` is non-NULL for a section entry.
        if !unsafe { do_create(value, name) } {
            // SAFETY: a compile-time-constant site and this thread's own error queue.
            unsafe { raise_site(&ASN_MOID_38) };
            return 0;
        }
        i += 1;
    }

    1
}

/// `void ASN1_add_oid_module(void)`.
///
/// One `CONF_module_add`, and the two function pointers are what make this module's registration
/// observable: `CONF_modules_load` calls `oid_module_init`, and `CONF_modules_unload` calls
/// `oid_module_finish`.
#[no_mangle]
pub extern "C" fn ASN1_add_oid_module() {
    guard_ffi((), || {
        // The two callbacks are the registry's declared types rather than casts: `ConfInitFn`
        // and `ConfFinishFn` are `unsafe extern "C" fn` with exactly these signatures, so the
        // coercion here is a subtype check rather than a `transmute`. The registry never calls
        // them itself, which is why the callbacks carry their own `unsafe`.
        //
        // SAFETY: the name is a static NUL-terminated string.
        unsafe {
            CONF_module_add(
                c"oid_section".as_ptr(),
                Some(oid_module_init as ConfInitFn),
                Some(oid_module_finish as ConfFinishFn),
            )
        };
        // `CONF_module_add`'s answer is discarded, as the authority discards it. A failure here
        // means the registry could not allocate, which the next `CONF_modules_load` reports as
        // an unknown module name — the same place the authority reports it.
    })
}
