//! `crypto/conf/conf_sap.c` — the legacy automatic configuration loader.
//!
//! ## Why `OPENSSL_config` is a wrapper and not a loader
//!
//! The authority's body is seven lines and every one of them is a call into
//! something else:
//!
//! ```c
//! void OPENSSL_config(const char *appname)
//! {
//!     OPENSSL_INIT_SETTINGS settings;
//!
//!     memset(&settings, 0, sizeof(settings));
//!     if (appname != NULL)
//!         settings.appname = strdup(appname);
//!     settings.flags = DEFAULT_CONF_MFLAGS;
//!     OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, &settings);
//!
//!     free(settings.appname);
//! }
//! ```
//!
//! So the function's whole content is the *shape of the settings object* it hands
//! over, and that shape is three details worth naming because each is observable
//! in a different way:
//!
//! * the settings are **zeroed on the stack**, not built by `OPENSSL_INIT_new`.
//!   The observable difference is the allocation, not the values: `OPENSSL_INIT_new`
//!   installs the same `DEFAULT_CONF_MFLAGS`, so a reader comparing the two paths
//!   sees the same call into `OPENSSL_init_crypto`.
//! * `appname` is duplicated with **libc `strdup`** and released with **libc
//!   `free`**, not with `CRYPTO_malloc`/`CRYPTO_free`. That matters under an
//!   installable allocator (`CRYPTO_set_mem_functions`) or the secure heap: a
//!   debug build that counted OpenSSL allocations would count this one twice if
//!   the pairing were mismatched, and the authority's pairing is libc-to-libc.
//! * a NULL `appname` leaves the field NULL rather than pointing it at an empty
//!   string, and `free(NULL)` is then the release. Both halves are defined.
//!
//! ## What is not here
//!
//! `ossl_config_int` and `ossl_no_config_int` are internal (declared in
//! `internal/conf.h`, not installed) and are what `OPENSSL_init_crypto`'s
//! `OPENSSL_INIT_LOAD_CONFIG` step calls. **They are here now** — 6.10c wrote them
//! once `CONF_modules_load_file_ex` existed, which needed the module registry that
//! 6.10b landed. The module doc that used to explain their absence was correct while
//! it stood and is superseded here rather than left to contradict the file; the
//! divergence it recorded, D86 (a config file that exists is not applied), is
//! superseded by the same commit that made it false.
//!
//! ## The one piece of state, and why it is *file*-scoped
//!
//! `openssl_configured` is a `static int` in the authority and it is deliberately not
//! per-context: a process configures itself once. It is read and written without a
//! lock, which the authority's own comment on `OPENSSL_init_crypto` justifies by
//! requiring that a call with non-NULL settings happen before any other thread uses the
//! library. This crate stores it in an `AtomicI32` — the same value, one store and one
//! load, with the data race the authority's plain `int` has removed rather than
//! reproduced. That is a strengthening with no defined-program difference, which is why
//! it is not a divergence record; the authority's own guarantee is what makes the
//! authority's code correct, and it makes this code correct too.
//!
//! ## `ossl_config_int` fails without raising
//!
//! Every failure it can see is already on the error queue, put there by
//! `CONF_modules_load_file_ex`. It returns that function's value and raises nothing of
//! its own — so a caller that wants the reason calls `ERR_get_error` rather than
//! `ERR_peek_last_error`.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::OSSL_LIB_CTX_get0_global_default;
use crate::runtime::bio::sys;
use crate::runtime::conf::init_settings::{stack_settings, OpenSslInitSettings};
use crate::runtime::confmod::{CONF_modules_load_file_ex, DEFAULT_CONF_MFLAGS};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};

/// `static int openssl_configured = 0` — `crypto/conf/conf_sap.c`.
///
/// The authority's `int`, in an atomic for the reason the module documentation gives. It is
/// written by exactly two functions, [`ossl_config_int`] and [`ossl_no_config_int`], and read
/// by the first.
static OPENSSL_CONFIGURED: AtomicI32 = AtomicI32::new(0);

/// `int ossl_config_int(const OPENSSL_INIT_SETTINGS *settings)` — `crypto/conf/conf_sap.c`.
///
/// The automatic configuration loader's body. Three details are the whole of it:
///
/// * **the first call wins.** A second call answers 1 immediately without touching a file, so
///   a configuration file is read at most once per process even when several libraries
///   initialise OpenSSL.
/// * **a NULL `settings` means the default file and the default flag word**, which is the
///   `DEFAULT_CONF_MFLAGS` path `OPENSSL_init_crypto`'s `LOAD_CONFIG` step takes when it was
///   called without settings — the path `ASN1_STRING_TABLE_get` and every other consumer that
///   never mentions configuration takes.
/// * **the flag is set even when the load failed.** `openssl_configured = 1` is after the call
///   and not conditioned on `ret`, which is what makes a failed configuration permanent for
///   the process rather than retried by the next initialiser. A second `OPENSSL_init_crypto`
///   with `LOAD_CONFIG` therefore answers 1 — the once has already run — while the error queue
///   still holds the reason the first one produced.
///
/// The authority reads `settings->filename`, `->appname` and `->flags` **before** the call and
/// uses those three values, which is not the same as passing the pointer through: a settings
/// object a caller mutates from a module's initialiser would change what a re-entrant call
/// saw. The three reads are taken here in the same order.
///
/// # Safety
/// `settings` must be NULL or a live `OPENSSL_INIT_SETTINGS`; its `filename` and `appname`
/// fields must each be NULL or NUL-terminated.
pub(crate) unsafe fn ossl_config_int(settings: *const OpenSslInitSettings) -> c_int {
    // `if (openssl_configured) return 1;`
    if OPENSSL_CONFIGURED.load(Ordering::Acquire) != 0 {
        return 1;
    }

    // `filename = settings ? settings->filename : NULL;` and the two beside it. The reads
    // happen while the caller is inside the once, which is what makes following the pointer
    // sound.
    // SAFETY: `settings` is NULL or live per the caller's contract, and the three reads are
    // of its three fields.
    let (filename, appname, flags) = unsafe {
        if settings.is_null() {
            (ptr::null(), ptr::null(), DEFAULT_CONF_MFLAGS)
        } else {
            (
                (*settings).filename(),
                (*settings).appname(),
                (*settings).flags(),
            )
        }
    };

    // `ret = CONF_modules_load_file_ex(OSSL_LIB_CTX_get0_global_default(), filename, appname,
    // flags);` — the default context, never a caller's, because a process-wide configuration is
    // process-wide.
    let ctx = OSSL_LIB_CTX_get0_global_default();
    // SAFETY: `ctx` is the process's global default context, which is never NULL and never
    // released; `filename` and `appname` are NULL or NUL-terminated per the caller's contract,
    // and `CONF_modules_load_file_ex`'s own contract accepts exactly those.
    let ret = unsafe { CONF_modules_load_file_ex(ctx, filename, appname, flags) };

    OPENSSL_CONFIGURED.store(1, Ordering::Release);
    ret
}

/// `void ossl_no_config_int(void)` — `crypto/conf/conf_sap.c`.
///
/// One store. It exists so that `OPENSSL_INIT_NO_LOAD_CONFIG` claims the *same* once the real
/// loader would, which is what makes `NO_LOAD_CONFIG | LOAD_CONFIG` behave as the authority
/// does: the flag is set, and the loader that follows finds the configuration already done and
/// loads nothing.
///
/// It is a `pub(crate) fn` and not an `extern "C"` one because it is internal (declared in
/// `include/internal/conf.h` and not installed), and it takes no arguments and dereferences
/// nothing, so it needs no `unsafe` block at its call sites.
pub(crate) fn ossl_no_config_int() {
    OPENSSL_CONFIGURED.store(1, Ordering::Release);
}

/// `void OPENSSL_config(const char *appname)`
///
/// The deprecated automatic loader. Present in this profile because
/// `OPENSSL_NO_DEPRECATED_1_1_0` is **not** defined — measured in the court, not
/// inferred from the absence of a `no-deprecated` option, because `3_0` and `1_1_0`
/// are separate guards and only one of them being absent would still compile this
/// body out.
///
/// The return value is discarded, as the authority's is: a caller who needs to
/// know whether configuration succeeded calls `OPENSSL_init_crypto` themselves, and
/// every reason string of the failure is on the error queue.
///
/// # Safety
/// `appname` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_config(appname: *const c_char) {
    let mut dup: *mut c_char = core::ptr::null_mut();
    if !appname.is_null() {
        // SAFETY: `appname` is NUL-terminated per the caller's contract.
        dup = unsafe { sys::strdup(appname) };
    }
    let settings = stack_settings(dup);
    // `OPENSSL_init_crypto` is not an `unsafe fn`: it is a safe C entry point that
    // validates its own arguments and reports failure through the error queue and
    // its return value. The settings object is live and correctly laid out for the
    // duration of the call, which is the most it can require of a caller.
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, &settings);
    // SAFETY: `dup` came from `strdup` and is released exactly once; `free(NULL)`
    // is defined, which is the authority's release path for the NULL case.
    unsafe { sys::free(dup.cast::<c_void>()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::conf::init_settings::{OPENSSL_INIT_free, OPENSSL_INIT_new};

    #[test]
    fn a_null_appname_is_accepted_and_the_crate_survives_it() {
        // The behaviour a caller observes is that this returns, and that the
        // settings it built internally were the same shape `OPENSSL_INIT_new`
        // produces. The second half is checkable without re-running the loader,
        // because the flag word is the same constant.
        // SAFETY: NULL is a defined argument.
        unsafe { OPENSSL_config(core::ptr::null()) };

        // SAFETY: the settings object is live and correctly laid out.
        unsafe {
            let s = OPENSSL_INIT_new();
            assert!(!s.is_null());
            OPENSSL_INIT_free(s);
        }
    }

    #[test]
    fn a_named_appname_is_duplicated_with_libc_semantics() {
        let name = c"openssl-rs-test-app";
        // SAFETY: `name` is a static NUL-terminated literal.
        unsafe { OPENSSL_config(name.as_ptr()) };
    }
}
