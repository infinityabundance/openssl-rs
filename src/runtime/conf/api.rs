//! Phase 4 — CONF: `crypto/conf/conf_api.c`, the data model behind the public
//! configuration API.
//!
//! A `CONF` is one `LHASH_OF(CONF_VALUE)`. Entries with a non-NULL `name` are
//! key/value pairs keyed by `(section, name)`; entries with a NULL `name` are
//! *sections*, whose `value` is a `STACK_OF(CONF_VALUE)` of that section's pairs.
//! A section is therefore reachable two ways — from the hash by name, and from
//! each of its own entries via their `section` pointer — and both references must
//! agree, which is why `_CONF_add_string` deletes a replaced entry from the
//! stack as well as freeing it.
//!
//! ## The hash and order functions are observable
//!
//! `conf_value_hash` and `conf_value_cmp` decide bucket assignment and therefore
//! the order `def_dump` prints entries in and the `OPENSSL_LH_*stats*` numbers a
//! caller can ask for. They are reproduced from the authority's source rather
//! than replaced with a "better" hash. In particular `conf_value_cmp` compares
//! the `section` **pointers** first and only falls back to `strcmp` — so two
//! entries whose section strings are equal but whose pointers differ still reach
//! the `name` comparison, which is the behaviour callers' insertion order
//! depends on.

// The `_CONF_*` functions below carry the authority's own internal names from
// `crypto/conf/conf_api.c`. They are deliberately *not* `#[no_mangle]` — they
// are not exported symbols — so the compiler cannot tell that the spelling is
// intentional, and it warns. Renaming them would break the one-to-one
// correspondence between this module and the file it reconstructs, which is
// what makes the reconstruction reviewable against its authority.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::runtime::bio::sys;
use crate::runtime::lhash::{
    OPENSSL_LH_error, OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new, OPENSSL_LH_num_items,
    OPENSSL_LH_retrieve, OPENSSL_LH_set_down_load, OPENSSL_LH_strhash, OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};

use super::types::{Conf, ConfValue};

/// The `HashFunc` type `OPENSSL_LH_new` expects.
type LhHash = unsafe extern "C" fn(*const c_void) -> core::ffi::c_ulong;
/// The `CompFunc` type `OPENSSL_LH_new` expects.
type LhCmp = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// `static unsigned long conf_value_hash(const CONF_VALUE *v)`
///
/// `(strhash(section) << 2) ^ strhash(name)`, with `OPENSSL_LH_strhash(NULL) == 0`
/// — which is how a section entry and a lookup probe compare equal.
///
/// # Safety
/// `v` must point at a live `ConfValue` whose `section`/`name` are NULL or
/// NUL-terminated.
unsafe extern "C" fn conf_value_hash(v: *const c_void) -> core::ffi::c_ulong {
    let v = v as *const ConfValue;
    // SAFETY: `v` is a live `ConfValue` per the caller's contract.
    let (section, name) = unsafe { ((*v).section, (*v).name) };
    // SAFETY: both are NULL or NUL-terminated, which `OPENSSL_LH_strhash` accepts.
    unsafe { (OPENSSL_LH_strhash(section) << 2) ^ OPENSSL_LH_strhash(name) }
}

/// `static int conf_value_cmp(const CONF_VALUE *a, const CONF_VALUE *b)`
///
/// Section pointers first, then section strings, then names — with a NULL name
/// (a section entry) ordering *before* any named entry in the same section.
///
/// # Safety
/// `a` and `b` must point at live `ConfValue`s.
unsafe extern "C" fn conf_value_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a as *const ConfValue;
    let b = b as *const ConfValue;
    // SAFETY: both are live `ConfValue`s per the caller's contract.
    let (sa, sb) = unsafe { ((*a).section, (*b).section) };
    if sa != sb {
        // SAFETY: both sections are NULL or NUL-terminated.
        let i = unsafe { sys::strcmp(sa, sb) };
        if i != 0 {
            return i;
        }
    }
    // SAFETY: as above.
    let (na, nb) = unsafe { ((*a).name, (*b).name) };
    if !na.is_null() && !nb.is_null() {
        // SAFETY: both names are NUL-terminated.
        return unsafe { sys::strcmp(na, nb) };
    }
    if na == nb {
        return 0;
    }
    if na.is_null() {
        -1
    } else {
        1
    }
}

/// Creates the `LHASH_OF(CONF_VALUE)` the model lives in.
///
/// A separate function so that `_CONF_new_data` and the CONF court's probes can
/// both reach it without either re-deriving the hash and comparison functions.
fn new_lhash() -> *mut OpenSslLhash {
    // The two callbacks are `extern "C"` functions with exactly the signatures
    // `OPENSSL_LH_new` declares, so the cast only adapts them to the generic
    // pointer signature the table stores.
    OPENSSL_LH_new(
        Some(conf_value_hash as LhHash),
        Some(conf_value_cmp as LhCmp),
    )
}

/// Builds the `ConfValue` probe the lookups use: a key with a NULL name.
fn probe(section: *const c_char, name: *const c_char) -> ConfValue {
    ConfValue {
        section: section as *mut c_char,
        name: name as *mut c_char,
        value: ptr::null_mut(),
    }
}

/// `CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section)`
///
/// The section *entry*, not its stack — a NULL `name` is what selects a section.
///
/// # Safety
/// `conf` NULL or live; `section` NULL or NUL-terminated.
pub(crate) unsafe fn _CONF_get_section(
    conf: *const Conf,
    section: *const c_char,
) -> *mut ConfValue {
    if conf.is_null() || section.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `conf` is live per the caller's contract.
    let data = unsafe { (*conf).data };
    if data.is_null() {
        return ptr::null_mut();
    }
    let vv = probe(section, ptr::null());
    // SAFETY: `data` is a live table whose items are `ConfValue`s of this layout.
    unsafe {
        OPENSSL_LH_retrieve(data, (&vv as *const ConfValue).cast::<c_void>()) as *mut ConfValue
    }
}

/// `STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf, const char *section)`
///
/// # Safety
/// As [`_CONF_get_section`].
pub(crate) unsafe fn _CONF_get_section_values(
    conf: *const Conf,
    section: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: forwarded under the caller's contract.
    let v = unsafe { _CONF_get_section(conf, section) };
    if v.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `v` is a live section entry, whose `value` is its stack.
    unsafe { (*v).value as *mut OpenSslStack }
}

/// `int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value)`
///
/// Pushes the entry onto the section's stack and inserts it into the hash. When
/// the hash already held an equal key, the *existing* entry is removed from the
/// stack and freed, so the two references never diverge.
///
/// The order matters: the push happens first, so a failure there leaves the hash
/// untouched; and the replaced entry is freed only after it has been unlinked
/// from the stack.
///
/// # Safety
/// `conf` live with a non-NULL `data`; `section` a live section entry; `value` a
/// freshly allocated entry the caller gives up ownership of.
pub(crate) unsafe fn _CONF_add_string(
    conf: *mut Conf,
    section: *mut ConfValue,
    value: *mut ConfValue,
) -> c_int {
    // SAFETY: `section` is a live section entry whose `value` is its stack.
    let ts = unsafe { (*section).value as *mut OpenSslStack };
    // SAFETY: `value` is live and owned by this call from here on.
    unsafe { (*value).section = (*section).section };
    // SAFETY: `ts` is a live stack and `value` outlives the push.
    if unsafe { OPENSSL_sk_push(ts, value.cast::<c_void>()) } == 0 {
        return 0;
    }
    // SAFETY: `conf` is live and `value` is a live entry.
    let old = unsafe { OPENSSL_LH_insert((*conf).data, value.cast::<c_void>()) };
    if !old.is_null() {
        // SAFETY: the returned entry is the one that was in the table, and it is
        // also on the section's stack because a previous insert put it there.
        unsafe {
            OPENSSL_sk_delete_ptr(ts, old);
            let old = old as *mut ConfValue;
            CRYPTO_free((*old).name.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*old).value.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free(old.cast::<c_void>(), ptr::null(), 0);
        }
    }
    1
}

/// `static CONF_VALUE *lookup(const CONF *conf, const char *section, const char *name)`
///
/// # Safety
/// `conf` live with a non-NULL `data`; `section`/`name` NUL-terminated.
unsafe fn lookup(conf: *const Conf, section: *const c_char, name: *const c_char) -> *mut ConfValue {
    let vv = probe(section, name);
    // SAFETY: `conf` is live and `data` is a live table of `ConfValue`s.
    unsafe {
        OPENSSL_LH_retrieve((*conf).data, (&vv as *const ConfValue).cast::<c_void>())
            as *mut ConfValue
    }
}

/// `char *_CONF_get_string(const CONF *conf, const char *section, const char *name)`
///
/// Three lookups in a fixed order, and each one is observable:
///
/// 1. the named section, if `section` is non-NULL;
/// 2. if that section is the literal `"ENV"`, the environment;
/// 3. the `"default"` section.
///
/// A NULL `conf` goes straight to the environment, which is what makes
/// `CONF_get_string(NULL, group, name)` a defined call rather than a fault.
///
/// # Safety
/// `conf` NULL or live; `section`/`name` NULL or NUL-terminated.
pub(crate) unsafe fn _CONF_get_string(
    conf: *const Conf,
    section: *const c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return ptr::null_mut();
    }
    if conf.is_null() {
        if section.is_null() {
            // The authority ignores `section` here and reads the environment.
            // SAFETY: `name` is NUL-terminated.
            return unsafe { crate::runtime::getenv::ossl_safe_getenv(name) };
        }
        // SAFETY: `name` is NUL-terminated.
        return unsafe { crate::runtime::getenv::ossl_safe_getenv(name) };
    }
    // SAFETY: `conf` is live per the caller's contract.
    if unsafe { (*conf).data }.is_null() {
        return ptr::null_mut();
    }
    if !section.is_null() {
        // SAFETY: `conf`, `section` and `name` are live; `data` is non-NULL.
        let v = unsafe { lookup(conf, section, name) };
        if !v.is_null() {
            // SAFETY: a named entry's `value` is its string.
            return unsafe { (*v).value };
        }
        let env = c"ENV";
        // SAFETY: `section` is NUL-terminated.
        if unsafe { sys::strcmp(section, env.as_ptr()) } == 0 {
            // SAFETY: `name` is NUL-terminated.
            let p = unsafe { crate::runtime::getenv::ossl_safe_getenv(name) };
            if !p.is_null() {
                return p;
            }
        }
    }
    let default = c"default";
    // SAFETY: `conf` and `name` are live; the default section may not exist.
    let v = unsafe { lookup(conf, default.as_ptr(), name) };
    if v.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a named entry's `value` is its string.
    unsafe { (*v).value }
}

/// `static void value_free_stack_doall(CONF_VALUE *a)`
///
/// Frees a *section* entry: every pair on its stack, then the stack, then the
/// section's own name and the entry. A named entry is ignored, because the first
/// phase of the free walk already removed those from the hash and their storage
/// belongs to the section's stack.
///
/// # Safety
/// `a` must be a live entry that is still present in the table.
unsafe extern "C" fn value_free_stack_doall(a: *mut c_void) {
    let a = a as *mut ConfValue;
    // SAFETY: `a` is live per the callback's contract.
    if !unsafe { (*a).name }.is_null() {
        return;
    }
    // SAFETY: a NULL `name` makes `value` the section's stack.
    let sk = unsafe { (*a).value as *mut OpenSslStack };
    // SAFETY: `sk` is a live stack of `ConfValue`s.
    unsafe {
        for i in (0..OPENSSL_sk_num(sk)).rev() {
            let vv = OPENSSL_sk_value(sk, i) as *mut ConfValue;
            CRYPTO_free((*vv).value.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*vv).name.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free(vv.cast::<c_void>(), ptr::null(), 0);
        }
        OPENSSL_sk_free(sk);
        CRYPTO_free((*a).section.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(a.cast::<c_void>(), ptr::null(), 0);
    }
}

/// Holds the table being walked by [`value_free_hash`].
///
/// The authority passes `conf->data` as the `doall` argument, so no global is
/// needed there; this module's `doall` goes through `OPENSSL_LH_doall_arg`, whose
/// argument is a `*mut c_void`, so the table pointer is threaded through it.
///
/// # Safety
/// `a` must be a live entry in the table passed as `arg`.
unsafe extern "C" fn value_free_hash(a: *mut c_void, arg: *mut c_void) {
    let a = a as *mut ConfValue;
    // SAFETY: `a` is live per the callback's contract.
    if unsafe { (*a).name }.is_null() {
        return;
    }
    let data = arg as *mut OpenSslLhash;
    // SAFETY: `data` is the live table the walk is running over, and `a` is an
    // entry in it. `OPENSSL_LH_delete` returns the entry without freeing it.
    unsafe { crate::runtime::lhash::OPENSSL_LH_delete(data, a.cast::<c_void>()) };
}

/// `int _CONF_new_data(CONF *conf)`
///
/// Idempotent: an existing table is left alone.
///
/// # Safety
/// `conf` NULL or live.
pub(crate) unsafe fn _CONF_new_data(conf: *mut Conf) -> c_int {
    if conf.is_null() {
        return 0;
    }
    // SAFETY: `conf` is live per the caller's contract.
    if unsafe { (*conf).data }.is_null() {
        let data = new_lhash();
        if data.is_null() {
            return 0;
        }
        // SAFETY: `conf` is live and writable.
        unsafe { (*conf).data = data };
    }
    1
}

/// `void _CONF_free_data(CONF *conf)`
///
/// Two walks, and their order is the point:
///
/// 1. every *named* entry is deleted from the hash — but not freed, because the
///    section's stack still owns it;
/// 2. what remains is only sections, and each is freed together with its stack,
///    which is what releases the named entries.
///
/// Deleting in the first walk is why the table's `down_load` is set to 0 first:
/// with contraction enabled, deleting during iteration would rehash the table
/// being walked. The context is walked by a snapshotting iterator, but the
/// authority's own guard is reproduced because `down_load` is observable to a
/// caller that inspects the table's statistics mid-walk.
///
/// `conf->data` is **not** cleared, and neither is `conf->includedir`: the
/// authority leaves both dangling, and a second call is a caller-side
/// double-free. That is the authority's contract, so it is reproduced rather than
/// quietly made idempotent.
///
/// # Safety
/// `conf` NULL or live; the caller must not use the configuration's data
/// afterwards.
pub(crate) unsafe fn _CONF_free_data(conf: *mut Conf) {
    if conf.is_null() {
        return;
    }
    // SAFETY: `conf` is live; `includedir` is NULL or a `CRYPTO_malloc` buffer.
    unsafe {
        CRYPTO_free((*conf).includedir.cast::<c_void>(), ptr::null(), 0);
    }
    // SAFETY: `conf` is live.
    let data = unsafe { (*conf).data };
    if data.is_null() {
        return;
    }
    // The "evil thing" the authority's comment names: a nonzero down_load would
    // let the deletes below contract the table while it is being walked.
    // SAFETY: `data` is a live table.
    unsafe { OPENSSL_LH_set_down_load(data, 0) };
    // SAFETY: `data` is live and `value_free_hash` deletes only entries it is
    // handed, which the walk tolerates (see the module doc for the snapshot).
    unsafe {
        crate::runtime::lhash::OPENSSL_LH_doall_arg(
            data,
            Some(value_free_hash),
            data.cast::<c_void>(),
        );
        crate::runtime::lhash::OPENSSL_LH_doall(data, Some(value_free_stack_doall));
        OPENSSL_LH_free(data);
    }
}

/// `CONF_VALUE *_CONF_new_section(CONF *conf, const char *section)`
///
/// Returns NULL if the section already exists, because the insert returns the
/// entry it replaced. The stack is allocated first so that a failure to allocate
/// the entry or its name does not need to unwind a partially built stack — and
/// the error path deliberately does *not* free `v->section`, which the authority
/// would free uninitialised; see `docs/SECURITY_DIVERGENCE_POLICY.md`.
///
/// # Safety
/// `conf` live with a non-NULL `data`; `section` NUL-terminated.
pub(crate) unsafe fn _CONF_new_section(conf: *mut Conf, section: *const c_char) -> *mut ConfValue {
    let sk = OPENSSL_sk_new_null();
    if sk.is_null() {
        return ptr::null_mut();
    }
    let v = CRYPTO_malloc(core::mem::size_of::<ConfValue>(), ptr::null(), 0).cast::<ConfValue>();
    if v.is_null() {
        // SAFETY: `sk` is a live, empty stack.
        unsafe { OPENSSL_sk_free(sk) };
        return ptr::null_mut();
    }
    // SAFETY: `section` is NUL-terminated per the caller's contract.
    let len = unsafe { sys::strlen(section) } + 1;
    let name = CRYPTO_malloc(len, ptr::null(), 0).cast::<c_char>();
    if name.is_null() {
        // SAFETY: `sk` is a live empty stack and `v` a live allocation. The
        // authority's path would free the *uninitialised* `v->section` here; not
        // doing so is the recorded safer divergence.
        unsafe {
            OPENSSL_sk_free(sk);
            CRYPTO_free(v.cast::<c_void>(), ptr::null(), 0);
        }
        return ptr::null_mut();
    }
    // SAFETY: `name` is `len` bytes and `section` has `len` bytes including its
    // terminator.
    unsafe {
        sys::memcpy(name.cast::<c_void>(), section.cast::<c_void>(), len);
        (*v).section = name;
        (*v).name = ptr::null_mut();
        (*v).value = sk.cast::<c_char>();
    }
    // SAFETY: `conf` and `v` are live, and `v` is a valid section entry.
    let vv = unsafe { OPENSSL_LH_insert((*conf).data, v.cast::<c_void>()) };
    // SAFETY: `conf` is live; `data` is a live table.
    if !vv.is_null() || unsafe { OPENSSL_LH_error((*conf).data) } > 0 {
        // SAFETY: see the function doc — the authority frees `v->section` here,
        // which we do only because it *is* initialised on this path.
        unsafe {
            OPENSSL_sk_free(sk);
            CRYPTO_free((*v).section.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free(v.cast::<c_void>(), ptr::null(), 0);
        }
        return ptr::null_mut();
    }
    v
}

/// `long _CONF_get_number(const CONF *conf, const char *section, const char *name)`
///
/// A convenience wrapper that swallows the error queue: it marks, calls
/// `NCONF_get_number_e`, pops back to the mark, and reports 0 for any failure.
///
/// # Safety
/// `conf` NULL or live; `section`/`name` NULL or NUL-terminated.
pub(crate) unsafe fn _CONF_get_number(
    conf: *const Conf,
    section: *const c_char,
    name: *const c_char,
) -> c_long {
    let mut result: c_long = 0;
    crate::runtime::err::ERR_set_mark();
    // SAFETY: forwarded under the caller's contract.
    let status = unsafe { super::lib::NCONF_get_number_e(conf, section, name, &mut result) };
    crate::runtime::err::ERR_pop_to_mark();
    if status == 0 {
        0
    } else {
        result
    }
}

/// The number of entries in the model, for the module's own tests and for
/// `def_destroy`'s bookkeeping. Not part of the public API.
///
/// # Safety
/// `conf` NULL or live.
pub(crate) unsafe fn _CONF_num_items(conf: *const Conf) -> core::ffi::c_ulong {
    if conf.is_null() {
        return 0;
    }
    // SAFETY: `conf` is live per the caller's contract.
    let data = unsafe { (*conf).data };
    if data.is_null() {
        return 0;
    }
    // SAFETY: `data` is a live table.
    unsafe { OPENSSL_LH_num_items(data) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::conf::def::NCONF_default;
    use crate::runtime::conf::lib::{NCONF_free, NCONF_new_ex};

    #[test]
    fn a_section_entry_is_distinguishable_from_a_named_entry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // SAFETY: the default method's `create` allocates and initialises.
        let conf = unsafe { NCONF_new_ex(ptr::null_mut(), NCONF_default()) };
        assert!(!conf.is_null());
        // SAFETY: `conf` came from `NCONF_new_ex` above and is still live.
        assert_eq!(unsafe { _CONF_num_items(conf) }, 0, "no data until a load");
        // SAFETY: `conf` is live; a NULL table makes every lookup a NULL answer.
        unsafe {
            assert!(_CONF_get_section(conf, c"anything".as_ptr()).is_null());
            assert!(_CONF_get_section_values(conf, c"anything".as_ptr()).is_null());
            assert!(_CONF_get_string(conf, c"g".as_ptr(), c"n".as_ptr()).is_null());
            assert_eq!(_CONF_get_number(conf, c"g".as_ptr(), c"n".as_ptr()), 0);
            // `_CONF_new_data` is what a load calls, and it is idempotent.
            assert_eq!(_CONF_new_data(conf), 1);
            assert_eq!(_CONF_new_data(conf), 1);
            assert_eq!(_CONF_num_items(conf), 0);
            // A NULL `conf` consults the environment, not the model.
            std::env::set_var("OPENSSL_RS_CONF_PROBE", "env-value");
            let got = _CONF_get_string(
                ptr::null(),
                c"g".as_ptr(),
                c"OPENSSL_RS_CONF_PROBE".as_ptr(),
            );
            assert!(!got.is_null());
            assert_eq!(std::ffi::CStr::from_ptr(got).to_str()?, "env-value");
            // A NULL name is always NULL, even with a NULL configuration.
            assert!(_CONF_get_string(ptr::null(), ptr::null(), ptr::null()).is_null());
            NCONF_free(conf);
        }
        Ok(())
    }
}
