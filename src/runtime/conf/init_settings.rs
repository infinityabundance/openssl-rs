//! Phase 4 — `OPENSSL_INIT_SETTINGS`, the object that carries configuration
//! parameters into `OPENSSL_init_crypto`.
//!
//! ## Why these five symbols are in the CONF stratum
//!
//! They are defined in `crypto/conf/conf_lib.c`, and they exist because the
//! options that steer configuration loading — `OPENSSL_INIT_LOAD_CONFIG` and
//! `OPENSSL_INIT_NO_LOAD_CONFIG` — are passed to `OPENSSL_init_crypto` together
//! with a *settings object* rather than as plain arguments. This module is their
//! home for the same reason the rest of `conf_lib.c` is: they are the boundary
//! between the configuration reader and the initialiser.
//!
//! ## The two allocators, and why they differ
//!
//! The authority's comment is explicit: these routines call the C library's
//! `malloc`, `strdup` and `free` rather than `CRYPTO_malloc` and friends, so that
//! a settings object created *before* `OPENSSL_init_crypto` runs is not allocated
//! by a callback that a later `CRYPTO_set_mem_functions` would have replaced. The
//! object would otherwise have to be freed by a different allocator than the one
//! that produced it. That is reproduced exactly, including that the freeing call
//! is `free` and not `CRYPTO_free`.
//!
//! ## Layout
//!
//! `OPENSSL_INIT_SETTINGS` is opaque in the public headers; its definition lives
//! in `include/internal/conf.h` as `{ char *filename; char *appname; unsigned long
//! flags; }`. The layout is internal, so nothing observable depends on it, but it
//! is transcribed rather than invented, because `OPENSSL_config` builds one **by
//! value** on the stack and passes its address to `OPENSSL_init_crypto`.

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;

use crate::ffi::guard_ffi;

use super::super::bio::sys;

/// The C `struct ossl_init_settings_st`, private to the library.
#[repr(C)]
pub struct OpenSslInitSettings {
    /// The configuration file to load, or NULL for the default.
    filename: *mut c_char,
    /// The application name whose section is used, or NULL.
    appname: *mut c_char,
    /// The `CONF_MFLAGS_*` word the loader is called with.
    flags: c_ulong,
}

// The three readers `crypto/conf/conf_sap.c`'s `ossl_config_int` needs. The authority's
// function reads the fields directly because it is compiled into the same library; the
// fields are private here, so the readers stand where the C's member access stands. Each
// is called only on a non-NULL `settings`, which is the caller's contract.
impl OpenSslInitSettings {
    /// `settings->filename`.
    pub(crate) fn filename(&self) -> *const c_char {
        self.filename
    }

    /// `settings->appname`.
    pub(crate) fn appname(&self) -> *const c_char {
        self.appname
    }

    /// `settings->flags`.
    pub(crate) fn flags(&self) -> c_ulong {
        self.flags
    }
}

/// An `OPENSSL_INIT_SETTINGS` built on the stack, the way `OPENSSL_config` builds
/// one.
///
/// The struct is opaque in the installed headers, so only this module can construct
/// it; `crypto/conf/conf_sap.c` builds it with `memset(&settings, 0, ...)` plus two
/// assignments, and the values it installs are exactly `DEFAULT_CONF_MFLAGS` and
/// the caller's duplicated application name. This constructor exists so that
/// `OPENSSL_config` can hand over the same three fields without a second definition
/// of what "the default settings" means, and so that the `appname` the caller
/// releases is the one this module's `strdup` produced.
///
/// `filename` is NULL, which is the authority's `memset` result and therefore means
/// "the default configuration file".
pub(crate) fn stack_settings(appname: *mut c_char) -> OpenSslInitSettings {
    OpenSslInitSettings {
        filename: ptr::null_mut(),
        appname,
        flags: DEFAULT_CONF_MFLAGS,
    }
}

/// `DEFAULT_CONF_MFLAGS` — the flag word `OPENSSL_INIT_new` installs.
///
/// `CONF_MFLAGS_DEFAULT_SECTION | CONF_MFLAGS_IGNORE_MISSING_FILE |
/// CONF_MFLAGS_IGNORE_RETURN_CODES`, which is why a settings object that a caller
/// never touches still tolerates a missing configuration file and a failing
/// module.
///
/// `crypto/conf/conf_mod.c`'s Rust home composes the same value from the four
/// individual `CONF_MFLAGS_*` bits it documents, because it needs those bits
/// separately; both are the authority's single definition in
/// `include/internal/conf.h`, and the two spellings are checked against each other
/// by a unit test in that module rather than trusted.
pub(crate) const DEFAULT_CONF_MFLAGS: c_ulong = 0x20 | 0x10 | 0x2;

/// `OPENSSL_INIT_SETTINGS *OPENSSL_INIT_new(void)`
///
/// The object is zeroed and then has `flags` set, so a caller sees
/// `filename == NULL`, `appname == NULL` and the default flag word.
///
/// Allocated with the C library's `malloc`, as the authority's comment requires:
/// see the module documentation.
#[no_mangle]
pub extern "C" fn OPENSSL_INIT_new() -> *mut OpenSslInitSettings {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: a plain allocation request of a known size.
        let raw = unsafe { sys::malloc(core::mem::size_of::<OpenSslInitSettings>()) };
        let ret = raw.cast::<OpenSslInitSettings>();
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ret` is a fresh block of exactly this type, so it is writable
        // for its own size.
        unsafe {
            sys::memset(
                ret.cast::<c_void>(),
                0,
                core::mem::size_of::<OpenSslInitSettings>(),
            );
            (*ret).flags = DEFAULT_CONF_MFLAGS;
        }
        ret
    })
}

/// `int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings, const char *filename)`
///
/// A NULL `filename` clears the field rather than failing, and the *old* string
/// is released before the new one is installed — so a caller may pass the pointer
/// it is replacing without a use-after-free only because the copy is made first.
///
/// # Safety
/// `settings` must be a live object from [`OPENSSL_INIT_new`]; `filename` must be
/// NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_set_config_filename(
    settings: *mut OpenSslInitSettings,
    filename: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `settings` is NULL or a live `OpenSslInitSettings` per this
        // function's contract; `as_mut` yields `None` for NULL and otherwise
        // borrows that live object for the closure's lifetime.
        let Some(s) = (unsafe { settings.as_mut() }) else {
            return 0;
        };
        let mut newname: *mut c_char = ptr::null_mut();
        if !filename.is_null() {
            // SAFETY: `filename` is NUL-terminated per the caller's contract, and
            // `strdup` allocates through the C library.
            newname = unsafe { sys::strdup(filename) };
            if newname.is_null() {
                return 0;
            }
        }
        // SAFETY: `s` is live; the previous string is whatever this function or
        // `OPENSSL_INIT_free` installed, and `free` is the matching deallocator.
        unsafe {
            sys::free(s.filename.cast::<c_void>());
            s.filename = newname;
        }
        1
    })
}

/// `void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings, unsigned long flags)`
///
/// # Safety
/// `settings` must be a live object from [`OPENSSL_INIT_new`].
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_set_config_file_flags(
    settings: *mut OpenSslInitSettings,
    flags: c_ulong,
) {
    guard_ffi((), || {
        // SAFETY: `settings` is live per the caller's contract.
        if let Some(s) = unsafe { settings.as_mut() } {
            s.flags = flags;
        }
    })
}

/// `int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings, const char *appname)`
///
/// # Safety
/// `settings` must be a live object from [`OPENSSL_INIT_new`]; `appname` must be
/// NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_set_config_appname(
    settings: *mut OpenSslInitSettings,
    appname: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `settings` is NULL or a live `OpenSslInitSettings` per this
        // function's contract; `as_mut` yields `None` for NULL and otherwise
        // borrows that live object for the closure's lifetime.
        let Some(s) = (unsafe { settings.as_mut() }) else {
            return 0;
        };
        let mut newname: *mut c_char = ptr::null_mut();
        if !appname.is_null() {
            // SAFETY: `appname` is NUL-terminated per the caller's contract.
            newname = unsafe { sys::strdup(appname) };
            if newname.is_null() {
                return 0;
            }
        }
        // SAFETY: `s` is live; `free` matches the `strdup` that produced the old
        // string.
        unsafe {
            sys::free(s.appname.cast::<c_void>());
            s.appname = newname;
        }
        1
    })
}

/// `void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings)`
///
/// Frees both strings and the object. A NULL argument is defined and returns.
///
/// # Safety
/// `settings` must be NULL or a live object from [`OPENSSL_INIT_new`] that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_free(settings: *mut OpenSslInitSettings) {
    guard_ffi((), || {
        // SAFETY: `settings` is NULL or a live, not-yet-freed
        // `OpenSslInitSettings` per this function's contract; `as_mut` yields
        // `None` for NULL and otherwise borrows that live object.
        let Some(s) = (unsafe { settings.as_mut() }) else {
            return;
        };
        // SAFETY: `s` is live and owns both strings; `free` matches their
        // `strdup`.
        unsafe {
            sys::free(s.filename.cast::<c_void>());
            sys::free(s.appname.cast::<c_void>());
            sys::free(settings.cast::<c_void>());
        }
    })
}

/// The field offsets are what `OPENSSL_config` relies on when it builds the
/// object by value and hands its address to `OPENSSL_init_crypto`, so they are
/// pinned rather than left implicit.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_the_internal_header() {
        assert_eq!(core::mem::offset_of!(OpenSslInitSettings, filename), 0);
        assert_eq!(
            core::mem::offset_of!(OpenSslInitSettings, appname),
            core::mem::size_of::<usize>()
        );
        assert_eq!(core::mem::size_of::<OpenSslInitSettings>(), 24);
        assert_eq!(DEFAULT_CONF_MFLAGS, 0x32);
    }

    /// A fresh object has no name, no appname and the default flags, and a NULL
    /// filename/appname *clears* rather than fails.
    #[test]
    fn fresh_object_defaults_and_null_clears() {
        let s = OPENSSL_INIT_new();
        assert!(!s.is_null());
        // SAFETY: `s` came from `OPENSSL_INIT_new`.
        unsafe {
            assert!((*s).filename.is_null());
            assert!((*s).appname.is_null());
            assert_eq!((*s).flags, DEFAULT_CONF_MFLAGS);
            assert_eq!(set_config_flags_probe(s), 1);
            assert_eq!(OPENSSL_INIT_set_config_filename(s, c"a.cnf".as_ptr()), 1);
            assert_eq!(strlen_probe((*s).filename), 5);
            assert_eq!(OPENSSL_INIT_set_config_filename(s, ptr::null()), 1);
            assert!((*s).filename.is_null());
            OPENSSL_INIT_free(s);
        }
    }

    /// # Safety
    /// `s` must be live.
    unsafe fn set_config_flags_probe(s: *mut OpenSslInitSettings) -> c_int {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { OPENSSL_INIT_set_config_file_flags(s, 7) };
        // SAFETY: as above.
        unsafe { ((*s).flags == 7) as c_int }
    }

    /// # Safety
    /// `p` must be NUL-terminated.
    unsafe fn strlen_probe(p: *const c_char) -> usize {
        // SAFETY: the caller guarantees NUL termination.
        unsafe { sys::strlen(p) }
    }
}
