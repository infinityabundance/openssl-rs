//! `OSSL_DISPATCH` — the function table the core hands a provider, and a provider
//! hands the core.
//!
//! Both directions of the OpenSSL 3 provider interface are a **table of
//! `(id, function pointer)` pairs terminated by id 0**. The core builds one for
//! each provider it loads (6.8's `crypto/provider_core.c`), and a provider builds
//! one for the core in its `OSSL_provider_init` (the same stratum). This module
//! holds the type, the terminator, and the seven ids this subphase needs; the
//! rest of the ids belong with the code that reads them.
//!
//! ## The accessor is a cast, not a search
//!
//! The authority's `OSSL_CORE_MAKE_FUNC` expands to
//!
//! ```c
//! typedef type (OSSL_FUNC_##name##_fn) args;
//! static ossl_unused ossl_inline OSSL_FUNC_##name##_fn *OSSL_FUNC_##name(const OSSL_DISPATCH *opf)
//! { return (OSSL_FUNC_##name##_fn *)opf->function; }
//! ```
//!
//! — a plain cast of the *given* entry's function pointer, with no search. That
//! matters to how the callers are written: `ossl_bio_init_core` walks the table
//! itself, switches on `function_id`, and only then casts the entry it is holding.
//! [`lookup`] is the equivalent walk for the callers that want "the function with
//! this id" rather than "this entry's function", and it is the form 6.8 needs.
//!
//! ## Ids are a wire format
//!
//! The numeric ids are part of the interface: a provider compiled against a
//! different header set that numbered `OSSL_FUNC_BIO_READ_EX` differently would
//! be silently misread. They are copied from the admitted authority's
//! `core_dispatch.h` rather than derived, and the ones this subphase uses are the
//! seven `BIO_*` entries.

use core::ffi::{c_int, c_long, c_void};

/// `struct ossl_dispatch_st`, from `openssl/core_dispatch.h`.
///
/// `function` is `void (*)(void)` in C — the generic function-pointer type — and
/// every field of it is read by casting to the type the id names. A `*mut c_void`
/// is that same pointer for every purpose this crate has, and it avoids a
/// `transmute` at every read site.
#[repr(C)]
pub struct OsslDispatch {
    /// `int function_id` — one of the `OSSL_FUNC_*` values, or `OSSL_DISPATCH_END`.
    /// The C type is `int` and the ids are small positive integers.
    pub function_id: c_int,
    /// `void (*function)(void)`.
    pub function: *mut c_void,
}

// SAFETY: every `OSSL_DISPATCH` table in the authority is a `static const` array:
// fully initialised before it is published and never mutated afterwards. Its two
// fields are an integer and a function pointer, and the raw `*mut c_void` is the
// only reason this impl is needed -- it exists so that a read site does not need a
// `transmute` (see the field's documentation). Sharing such a table across threads
// therefore introduces no data race.
unsafe impl Sync for OsslDispatch {}

/// `#define OSSL_DISPATCH_END 0` — the terminator, and the reason a table is a
/// NUL-terminated array in everything but name.
pub const OSSL_DISPATCH_END: c_int = 0;

/// `OSSL_FUNC_BIO_READ_EX`
pub(crate) const OSSL_FUNC_BIO_READ_EX: c_int = 42;
/// `OSSL_FUNC_BIO_WRITE_EX`
pub(crate) const OSSL_FUNC_BIO_WRITE_EX: c_int = 43;
/// `OSSL_FUNC_BIO_UP_REF`
pub(crate) const OSSL_FUNC_BIO_UP_REF: c_int = 44;
/// `OSSL_FUNC_BIO_FREE`
pub(crate) const OSSL_FUNC_BIO_FREE: c_int = 45;
/// `OSSL_FUNC_BIO_PUTS`
pub(crate) const OSSL_FUNC_BIO_PUTS: c_int = 48;
/// `OSSL_FUNC_BIO_GETS`
pub(crate) const OSSL_FUNC_BIO_GETS: c_int = 49;
/// `OSSL_FUNC_BIO_CTRL`
pub(crate) const OSSL_FUNC_BIO_CTRL: c_int = 50;

// Phase 9 — the eight entropy and nonce up-calls `providers/common/provider_seeding.c` publishes
// and `providers/implementations/rands/drbg.c` consumes through the provider context. They are the
// only `core_dispatch.h` ids this crate takes from the `GET/CLEANUP_{USER_,}{ENTROPY,NONCE}` block,
// and they are *not* the `os*` seeding functions: names and numbers are read from
// `include/openssl/core_dispatch.h:177-191`, where the numbers are not contiguous with the block
// above (`100` is absent, and 96/97 precede 98/99 because the `CLEANUP_` pair was added first).
/// `OSSL_FUNC_CLEANUP_USER_ENTROPY` — `core_dispatch.h:177`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_cleanup_entropy`
pub(crate) const OSSL_FUNC_CLEANUP_USER_ENTROPY: c_int = 96;
/// `OSSL_FUNC_CLEANUP_USER_NONCE` — `core_dispatch.h:178`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_cleanup_nonce`
pub(crate) const OSSL_FUNC_CLEANUP_USER_NONCE: c_int = 97;
/// `OSSL_FUNC_GET_USER_ENTROPY` — `core_dispatch.h:179`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_get_entropy`
pub(crate) const OSSL_FUNC_GET_USER_ENTROPY: c_int = 98;
/// `OSSL_FUNC_GET_USER_NONCE` — `core_dispatch.h:180`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_get_nonce`
pub(crate) const OSSL_FUNC_GET_USER_NONCE: c_int = 99;
/// `OSSL_FUNC_GET_ENTROPY` — `core_dispatch.h:188`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_get_entropy`
pub(crate) const OSSL_FUNC_GET_ENTROPY: c_int = 101;
/// `OSSL_FUNC_CLEANUP_ENTROPY` — `core_dispatch.h:189`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_cleanup_entropy`
pub(crate) const OSSL_FUNC_CLEANUP_ENTROPY: c_int = 102;
/// `OSSL_FUNC_GET_NONCE` — `core_dispatch.h:190`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_get_nonce`
pub(crate) const OSSL_FUNC_GET_NONCE: c_int = 103;
/// `OSSL_FUNC_CLEANUP_NONCE` — `core_dispatch.h:191`.
#[allow(dead_code)] // the landing caller is `provider_seeding.c`'s `ossl_prov_cleanup_nonce`
pub(crate) const OSSL_FUNC_CLEANUP_NONCE: c_int = 104;

/// `int (*)(OSSL_CORE_BIO *bio, void *data, size_t data_len, size_t *bytes_read)`
pub(crate) type OsslFuncBioReadEx =
    unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *mut usize) -> c_int;
/// `int (*)(OSSL_CORE_BIO *bio, const void *data, size_t data_len, size_t *written)`
pub(crate) type OsslFuncBioWriteEx =
    unsafe extern "C" fn(*mut c_void, *const c_void, usize, *mut usize) -> c_int;
/// `int (*)(OSSL_CORE_BIO *bio, char *buf, int size)`
pub(crate) type OsslFuncBioGets =
    unsafe extern "C" fn(*mut c_void, *mut core::ffi::c_char, c_int) -> c_int;
/// `int (*)(OSSL_CORE_BIO *bio, const char *str)`
pub(crate) type OsslFuncBioPuts =
    unsafe extern "C" fn(*mut c_void, *const core::ffi::c_char) -> c_int;
/// `int (*)(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr)`
pub(crate) type OsslFuncBioCtrl =
    unsafe extern "C" fn(*mut c_void, c_int, c_long, *mut c_void) -> c_int;
/// `int (*)(OSSL_CORE_BIO *bio)`
pub(crate) type OsslFuncBioUpRef = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `int (*)(OSSL_CORE_BIO *bio)`
pub(crate) type OsslFuncBioFree = unsafe extern "C" fn(*mut c_void) -> c_int;

/// The function an entry holds, cast to the type its id names.
///
/// # Safety
/// `entry` must be a well-formed entry whose `function_id` is the id `T` belongs
/// to. A table's entries and the casts applied to them are a matched pair; casting
/// an entry to the wrong signature is the caller's error and is not detectable
/// here, exactly as the C macro cannot detect it.
pub(crate) unsafe fn entry_function<T>(entry: *const OsslDispatch) -> Option<T>
where
    T: Copy,
{
    if entry.is_null() {
        return None;
    }
    // SAFETY: `entry` is a live table entry per the caller's contract.
    let f = unsafe { (*entry).function };
    if f.is_null() {
        return None;
    }
    // The size of a function pointer is the size of a data pointer on every
    // platform this crate targets, which is what makes the authority's cast legal
    // and this one too. `transmute` between them is the same operation.
    if core::mem::size_of::<T>() != core::mem::size_of::<*mut c_void>() {
        return None;
    }
    // SAFETY: the two types have the same size (checked above), and the value came
    // from a table entry whose id names `T` per the caller's contract.
    Some(unsafe { core::mem::transmute_copy::<*mut c_void, T>(&f) })
}

#[allow(dead_code)] // unreachable until the stratum that calls it lands
/// Walk a table and answer the function whose entry has `id`, or NULL.
///
/// The walk stops at the first entry whose `function_id` is `OSSL_DISPATCH_END`, so
/// a table with no terminator is a caller error the authority shares (it would read
/// past the end too). A NULL table answers NULL rather than faulting, which is a
/// recorded safety divergence: the authority dereferences it.
///
/// # Safety
/// `table` must be NULL or point to a `OSSL_DISPATCH_END`-terminated array of
/// entries that remain live for the duration of the call.
pub(crate) unsafe fn lookup(table: *const OsslDispatch, id: c_int) -> *mut c_void {
    if table.is_null() {
        return core::ptr::null_mut();
    }
    let mut p = table;
    // SAFETY: the table is END-terminated per the caller's contract.
    unsafe {
        while (*p).function_id != OSSL_DISPATCH_END {
            if (*p).function_id == id {
                return (*p).function;
            }
            p = p.add(1);
        }
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn example(_bio: *mut c_void) -> c_int {
        7
    }

    #[test]
    fn lookup_finds_the_entry_with_the_id_and_stops_at_the_end() {
        static TABLE: [OsslDispatch; 3] = [
            OsslDispatch {
                function_id: OSSL_FUNC_BIO_FREE,
                function: core::ptr::null_mut(),
            },
            OsslDispatch {
                function_id: OSSL_FUNC_BIO_UP_REF,
                function: core::ptr::null_mut(),
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: core::ptr::null_mut(),
            },
        ];
        // SAFETY: `TABLE` is END-terminated and 'static.
        unsafe {
            assert!(lookup(TABLE.as_ptr(), OSSL_FUNC_BIO_UP_REF).is_null());
            assert!(lookup(TABLE.as_ptr(), OSSL_FUNC_BIO_CTRL).is_null());
            // A NULL table answers NULL rather than reading through it.
            assert!(lookup(core::ptr::null(), OSSL_FUNC_BIO_UP_REF).is_null());
            // A non-NULL function round-trips through the cast.
            assert!(entry_function::<OsslFuncBioUpRef>(&TABLE[0]).is_none());
        }
        let entry = OsslDispatch {
            function_id: OSSL_FUNC_BIO_FREE,
            function: example as *mut c_void,
        };
        // SAFETY: the entry's id names the same signature `T` is.
        let f = unsafe { entry_function::<OsslFuncBioFree>(&entry) };
        assert!(f.is_some(), "the entry holds a function of this signature");
        // SAFETY: `f` was just asserted `Some`; its parameter is a handle the
        // example ignores.
        assert_eq!(unsafe { f.unwrap_unchecked()(core::ptr::null_mut()) }, 7);
    }
}
