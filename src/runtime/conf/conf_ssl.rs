//! `crypto/conf/conf_ssl.c` — the `ssl_conf` configuration module's storage.
//!
//! ## What this file is, and what it deliberately is not
//!
//! The authority's `conf_ssl.c` has two halves:
//!
//! 1. a **static store** of named command sets, plus the three accessors this
//!    module implements (`conf_ssl_get`, `conf_ssl_name_find`, `conf_ssl_get_cmd`);
//! 2. a **CONF module** (`ssl_module_init`, `ssl_module_free`) that reads the
//!    configuration and fills that store, registered by `ossl_config_add_ssl_module`
//!    through `CONF_module_add`.
//!
//! Only the first half belongs to this stratum. The second calls
//! `CONF_imodule_get_value` and `CONF_module_add`, both of which Phase 4 handed to
//! Phase 6 because only the module registry constructs a `CONF_IMODULE` — so the
//! init function and the registration are Phase 6.9's, and they will be written
//! there against the store defined here. Writing an init that could not read the
//! module's own value would be a function whose only outcome is a failure branch.
//!
//! The **free** function is here, because it touches only this file's state and is
//! what the registry will hand to `CONF_module_add`.
//!
//! ## What a court can observe today, and the honest limit of it
//!
//! `conf_ssl_name_find` is fully observable: with the store empty it answers `0`
//! for every name, and `0` for NULL. The other two index into the store and
//! dereference it, so with the store empty they fault — which is the authority's
//! behaviour *and* the authority's reachability: nothing in the pinned profile can
//! call them before `ssl_conf` has been initialised, because the only caller is
//! libssl, which reads the store through `SSL_CONF` after the module ran.
//!
//! So `RT-COMP`, the court for this subphase, compares `conf_ssl_name_find` and
//! stops there, and the seal says so. The other two are transcribed because they
//! are the module's public surface and Phase 6.9 will need them the moment the
//! registry exists; they are not claimed to be courted.
//!
//! ## The structures, and why they are transcribed rather than invented
//!
//! `struct ssl_conf_name_st` and `struct ssl_conf_cmd_st` are *internal* — declared
//! in `conf_ssl.c` itself, not even in `conf_local.h` — so nothing outside this
//! translation unit ever sees them. Their layout is therefore free, and it is
//! transcribed anyway, field for field and in order, because the accessors hand
//! `SSL_CONF_CMD *` to libssl and the *count* and *order* of the entries in it are
//! what libssl reads. Getting those wrong is a silent misconfiguration rather than
//! a crash.

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::runtime::mem::CRYPTO_free;

/// `SSL_CONF_CMD` — one command and its argument, as libssl reads them.
///
/// Both strings are owned by the store and released by
/// [`ossl_config_ssl_module_free`].
#[repr(C)]
pub struct SslConfCmd {
    /// `char *cmd` — the command name, with any leading dot already stripped by
    /// the module's reader.
    pub cmd: *mut c_char,
    /// `char *arg` — the argument text, or NULL when the command had none.
    pub arg: *mut c_char,
}

/// `struct ssl_conf_name_st` — one named set of commands.
#[repr(C)]
pub struct SslConfName {
    /// `char *name` — the section name the set was declared in.
    pub name: *mut c_char,
    /// `SSL_CONF_CMD *cmds` — the set, in declaration order.
    pub cmds: *mut SslConfCmd,
    /// `size_t cmd_count`
    pub cmd_count: usize,
}

/// `static struct ssl_conf_name_st *ssl_names`
///
/// One static, not a per-`OSSL_LIB_CTX` slot: that is the authority's shape in
/// this version, and libssl's `SSL_CONF` reads it through the process-global
/// accessors below. An `AtomicPtr` rather than a `static mut` so that the
/// unsynchronised-write hazard is at least named at the definition rather than
/// implied — the authority writes it under no lock either, from configuration time,
/// which is before any other thread can be reading.
static SSL_NAMES: AtomicPtr<SslConfName> = AtomicPtr::new(core::ptr::null_mut());
/// `static size_t ssl_names_count`
static SSL_NAMES_COUNT: AtomicUsize = AtomicUsize::new(0);

/// `const SSL_CONF_CMD *conf_ssl_get(size_t idx, const char **name, size_t *cnt)`
///
/// The set at `idx`, with its name and count written through the out-parameters.
/// No bounds check, matching the authority: the caller is expected to have found
/// `idx` with [`conf_ssl_name_find`].
///
/// # Safety
/// `idx` must be in range for the current store — which is to say the store must
/// be non-empty and `idx` one of its indices. `name` and `cnt` must each be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn conf_ssl_get(
    idx: usize,
    name: *mut *const c_char,
    cnt: *mut usize,
) -> *const SslConfCmd {
    let names = SSL_NAMES.load(Ordering::Acquire);
    // SAFETY: the store is live per the caller's contract.
    let entry = unsafe { &*names.add(idx) };
    // SAFETY: both out-parameters are writable per the caller's contract.
    unsafe {
        *name = entry.name;
        *cnt = entry.cmd_count;
    }
    entry.cmds
}

/// `int conf_ssl_name_find(const char *name, size_t *idx)`
///
/// `1` with `*idx` set on a match, `0` otherwise — and `0` for a NULL name, which
/// is the authority's first check rather than a fault. Case-**sensitive**
/// (`strcmp`, not a case-insensitive compare), which is what makes the section
/// names in a configuration file exact.
///
/// # Safety
/// `name` must be NULL or a NUL-terminated C string; `idx` must be writable when a
/// match is possible.
#[no_mangle]
pub unsafe extern "C" fn conf_ssl_name_find(name: *const c_char, idx: *mut usize) -> c_int {
    if name.is_null() {
        return 0;
    }
    let names = SSL_NAMES.load(Ordering::Acquire);
    let count = SSL_NAMES_COUNT.load(Ordering::Acquire);
    let mut nm = names;
    for i in 0..count {
        // SAFETY: `nm` walks the live store, which holds `count` entries.
        if unsafe { crate::runtime::bio::sys::strcmp(name, (*nm).name) } == 0 {
            // SAFETY: `idx` is writable per the caller's contract.
            unsafe { *idx = i };
            return 1;
        }
        // SAFETY: `names` is a live array of `count` entries and `i < count`, so
        // the offset stays inside it.
        nm = unsafe { names.add(i + 1) };
    }
    0
}

/// `void conf_ssl_get_cmd(const SSL_CONF_CMD *cmd, size_t idx, char **cmdstr,
/// char **arg)`
///
/// The command and argument at `idx` of the set returned by [`conf_ssl_get`]. No
/// bounds check, as the authority: `idx` must be below the count that call
/// reported.
///
/// # Safety
/// `cmd` must be the pointer `conf_ssl_get` returned for a set whose count exceeds
/// `idx`, and both out-parameters must be writable.
#[no_mangle]
pub unsafe extern "C" fn conf_ssl_get_cmd(
    cmd: *const SslConfCmd,
    idx: usize,
    cmdstr: *mut *mut c_char,
    arg: *mut *mut c_char,
) {
    // SAFETY: `cmd` points at a live set of more than `idx` entries per the
    // caller's contract.
    let entry = unsafe { &*cmd.add(idx) };
    // SAFETY: both out-parameters are writable per the caller's contract.
    unsafe {
        *cmdstr = entry.cmd;
        *arg = entry.arg;
    }
}

/// `static void ssl_module_free(CONF_IMODULE *md)`
///
/// Releases every string the store owns, the command arrays, the name array, and
/// resets the store to empty. The argument is the module handle, which this
/// function does not read — the authority's signature takes one and ignores it too,
/// because the store is a file-level static rather than module state.
///
/// Exposed `pub(crate)` rather than `#[no_mangle]`: it is not an export, and
/// Phase 6.9's `CONF_module_add` will be handed this function -- which is why the
/// attribute below is a recorded gap rather than a tidiness: the only callers today
/// are this module's tests, and the moment the registry exists this becomes the
/// module's free hook.
///
/// # Safety
/// No live pointer obtained from [`conf_ssl_get`] or [`conf_ssl_get_cmd`] may be
/// used afterwards. This is the same contract the authority's version has.
#[allow(
    dead_code,
    reason = "the CONFIG module registry that calls this is Phase 6.9; the tests here are the only callers until it lands"
)]
pub(crate) unsafe fn ossl_config_ssl_module_free() {
    let names = SSL_NAMES.swap(core::ptr::null_mut(), Ordering::AcqRel);
    let count = SSL_NAMES_COUNT.swap(0, Ordering::AcqRel);
    if names.is_null() {
        return;
    }
    for i in 0..count {
        // SAFETY: `names` is a live array of `count` entries.
        let tname = unsafe { &mut *names.add(i) };
        // SAFETY: each pointer was produced by `OPENSSL_strdup`/`CRYPTO_calloc`
        // and is owned by this store.
        unsafe {
            CRYPTO_free(tname.name.cast(), core::ptr::null(), 0);
            for j in 0..tname.cmd_count {
                let cmd = &mut *tname.cmds.add(j);
                CRYPTO_free(cmd.cmd.cast(), core::ptr::null(), 0);
                CRYPTO_free(cmd.arg.cast(), core::ptr::null(), 0);
            }
            CRYPTO_free(tname.cmds.cast(), core::ptr::null(), 0);
        }
    }
    // SAFETY: the array itself came from `CRYPTO_calloc` in the module's reader,
    // which Phase 6.9 writes; the release belongs here so that the pairing is in
    // one file.
    unsafe { CRYPTO_free(names.cast(), core::ptr::null(), 0) };
}

/// Install a store, for the module's reader in Phase 6.9 and for the tests here.
///
/// # Safety
/// `names` must be NULL or an array of `count` live [`SslConfName`] values whose
/// strings and command arrays this module may subsequently free — that is, the
/// whole ownership must transfer. Any previous store is **not** freed by this
/// function; call [`ossl_config_ssl_module_free`] first, as the module's reader
/// does.
#[allow(
    dead_code,
    reason = "the `ssl_conf` reader in Phase 6.9 installs the store; the tests here are the only callers until it lands"
)]
pub(crate) unsafe fn ossl_config_ssl_module_install(names: *mut SslConfName, count: usize) {
    SSL_NAMES.store(names, Ordering::Release);
    SSL_NAMES_COUNT.store(count, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_strdup};
    use std::ffi::CString;

    fn empty_store_is_empty() {
        // SAFETY: the store is empty, so nothing is freed.
        unsafe { ossl_config_ssl_module_free() };
    }

    #[test]
    fn an_empty_store_finds_nothing_and_a_null_name_is_not_a_fault() {
        empty_store_is_empty();
        let Ok(wanted) = CString::new("SECLEVEL") else {
            unreachable!()
        };
        let mut idx = usize::MAX;
        // SAFETY: `wanted` is NUL-terminated and `idx` is writable.
        unsafe {
            assert_eq!(conf_ssl_name_find(wanted.as_ptr(), &mut idx), 0);
            assert_eq!(idx, usize::MAX, "a failed search must not write idx");
            assert_eq!(conf_ssl_name_find(core::ptr::null(), &mut idx), 0);
        }
    }

    #[test]
    fn the_search_is_case_sensitive_and_finds_what_was_installed() {
        empty_store_is_empty();
        // SAFETY: the source is a static NUL-terminated literal and the file/line
        // pair is the "internal allocation" marker the crate uses on these paths.
        let name = unsafe { CRYPTO_strdup(c"SECLEVEL".as_ptr(), core::ptr::null(), 0) };
        let cmds = CRYPTO_calloc(2, core::mem::size_of::<SslConfCmd>(), core::ptr::null(), 0)
            .cast::<SslConfCmd>();
        assert!(!name.is_null() && !cmds.is_null());
        // SAFETY: `cmds` has room for two entries; both strings are fresh.
        unsafe {
            (*cmds.add(0)).cmd = CRYPTO_strdup(c"cipher".as_ptr(), core::ptr::null(), 0);
            (*cmds.add(0)).arg = CRYPTO_strdup(c"DEFAULT".as_ptr(), core::ptr::null(), 0);
            (*cmds.add(1)).cmd = CRYPTO_strdup(c"level".as_ptr(), core::ptr::null(), 0);
            (*cmds.add(1)).arg = core::ptr::null_mut();
        }
        let names = CRYPTO_calloc(1, core::mem::size_of::<SslConfName>(), core::ptr::null(), 0)
            .cast::<SslConfName>();
        assert!(!names.is_null());
        // SAFETY: `names` has room for one entry.
        unsafe {
            (*names).name = name;
            (*names).cmds = cmds;
            (*names).cmd_count = 2;
            ossl_config_ssl_module_install(names, 1);
        }

        let Ok(exact) = CString::new("SECLEVEL") else {
            unreachable!()
        };
        let Ok(lower) = CString::new("seclevel") else {
            unreachable!()
        };
        let mut idx = usize::MAX;
        // SAFETY: both strings are NUL-terminated; the store is live.
        unsafe {
            assert_eq!(conf_ssl_name_find(exact.as_ptr(), &mut idx), 1);
            assert_eq!(idx, 0);
            // Case matters: the authority compares with `strcmp`.
            assert_eq!(conf_ssl_name_find(lower.as_ptr(), &mut idx), 0);
        }

        // SAFETY: the store is live and `idx` is in range for it.
        unsafe {
            let mut got_name: *const c_char = core::ptr::null();
            let mut got_count = 0usize;
            let set = conf_ssl_get(0, &mut got_name, &mut got_count);
            assert_eq!(set, cmds);
            assert_eq!(got_count, 2);
            let text = std::ffi::CStr::from_ptr(got_name);
            assert_eq!(text.to_str(), Ok("SECLEVEL"));

            let mut cmd: *mut c_char = core::ptr::null_mut();
            let mut arg: *mut c_char = core::ptr::null_mut();
            conf_ssl_get_cmd(set, 0, &mut cmd, &mut arg);
            assert_eq!(std::ffi::CStr::from_ptr(cmd).to_str(), Ok("cipher"));
            assert_eq!(std::ffi::CStr::from_ptr(arg).to_str(), Ok("DEFAULT"));
            // The second entry's argument is genuinely NULL, not "": the module's
            // reader stores what it read.
            conf_ssl_get_cmd(set, 1, &mut cmd, &mut arg);
            assert!(arg.is_null());

            ossl_config_ssl_module_free();
            // The store is empty again, so nothing is found.
            assert_eq!(conf_ssl_name_find(exact.as_ptr(), &mut idx), 0);
        }
    }
}
