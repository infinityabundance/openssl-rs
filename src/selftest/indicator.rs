//! Phase 6.11 — the indicator callback surface.
//!
//! `crypto/indicator_core.c` is fifty-four lines and does two things: store a
//! callback in the library context's slot 22, and read it back. The callback
//! itself is *invoked* elsewhere — by the code that performs an operation with an
//! approved/non-approved state to report — and that code is a provider-side
//! obligation, so this module implements the pair and the slot and nothing
//! pretends to report an indicator.
//!
//! The shape is deliberately the same as the self-test slot next door: a
//! `OPENSSL_zalloc`ed holder in a context slot, a setter that silently does
//! nothing when the slot cannot be read, and a getter whose output pointer is
//! optional. What is *not* the same is the callback's signature — it takes the
//! type and description as separate strings rather than as `OSSL_PARAM` entries —
//! and that is why the two live in one module with two callback types rather than
//! one generic holder.

use core::ffi::{c_char, c_void};

use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_INDICATOR_CB_INDEX};
use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::selftest::OsslIndicatorCallback;

/// The authority's translation unit, so a failing allocation records the
/// coordinates a consumer would see from the authority.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/indicator_core.c".as_ptr();
/// `OPENSSL_zalloc(sizeof(*cb))` is at `crypto/indicator_core.c:20` and
/// `OPENSSL_free(cb)` at 25.
const LINE_ZALLOC: core::ffi::c_int = 20;
const LINE_FREE: core::ffi::c_int = 25;

/// `struct indicator_cb_st` — one function pointer.
#[repr(C)]
pub(crate) struct IndicatorCb {
    /// `OSSL_INDICATOR_CALLBACK *cb`.
    cb: Option<OsslIndicatorCallback>,
}

/// `void *ossl_indicator_set_callback_new(OSSL_LIB_CTX *ctx)`
///
/// The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_indicator_set_callback_new(_ctx: *mut c_void) -> *mut IndicatorCb {
    CRYPTO_zalloc(core::mem::size_of::<IndicatorCb>(), FILE, LINE_ZALLOC).cast::<IndicatorCb>()
}

/// `void ossl_indicator_set_callback_free(void *cb)` — accepts NULL.
///
/// # Safety
/// `cb` must be NULL or a pointer returned by
/// [`ossl_indicator_set_callback_new`] and not already released.
pub(crate) unsafe fn ossl_indicator_set_callback_free(cb: *mut IndicatorCb) {
    if cb.is_null() {
        return;
    }
    // SAFETY: the block came from `CRYPTO_zalloc` in the constructor and is
    // released exactly once here.
    unsafe { CRYPTO_free(cb.cast::<c_void>(), FILE, LINE_FREE) };
}

/// `get_indicator_callback(libctx)` — the slot lookup.
fn slot(ctx: *mut c_void) -> *mut IndicatorCb {
    lib_ctx_get_data(ctx, OSSL_LIB_CTX_INDICATOR_CB_INDEX).cast::<IndicatorCb>()
}

/// `void OSSL_INDICATOR_set_callback(OSSL_LIB_CTX *libctx, OSSL_INDICATOR_CALLBACK *cb)`
///
/// Stores the callback in the **context's** slot. A context whose slot cannot be
/// read stores nothing, silently — the authority's own behaviour, and the same
/// one the self-test setter has.
///
/// # Safety
/// `libctx` must be NULL or a live context. The callback is stored, not owned: it
/// must remain valid for as long as the context may invoke it. The authority does
/// **not** clear the previous callback first, so passing a new one replaces it
/// outright and passing NULL removes it.
#[no_mangle]
pub unsafe extern "C" fn OSSL_INDICATOR_set_callback(
    libctx: *mut c_void,
    cb: Option<OsslIndicatorCallback>,
) {
    guard_ffi((), || {
        let icb = slot(libctx);
        if icb.is_null() {
            return;
        }
        // SAFETY: `icb` is a live callback holder owned by the context.
        unsafe { (*icb).cb = cb };
    })
}

/// `void OSSL_INDICATOR_get_callback(OSSL_LIB_CTX *libctx, OSSL_INDICATOR_CALLBACK **cb)`
///
/// The output pointer is optional, and answers NULL when the context has no slot
/// or no callback is set — so a caller cannot distinguish "no context" from
/// "nothing registered", which is the authority's behaviour too.
///
/// The parameter is a pointer to a **function pointer**, not a `void **`; see
/// `OSSL_SELF_TEST_get_callback` for why that distinction is written down.
///
/// # Safety
/// `libctx` must be NULL or a live context; `cb` must be NULL or point to
/// writable storage for a function pointer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_INDICATOR_get_callback(
    libctx: *mut c_void,
    cb: *mut Option<OsslIndicatorCallback>,
) {
    guard_ffi((), || {
        if cb.is_null() {
            return;
        }
        let icb = slot(libctx);
        // SAFETY: `cb` is writable per the caller's contract.
        unsafe {
            *cb = if icb.is_null() { None } else { (*icb).cb };
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new, OSSL_LIB_CTX_set0_default};

    /// Takes the crate-wide global-state lock. The one test that calls it
    /// installs a thread default and then resolves a **NULL** context through it;
    /// the NULL-context arm reads the process-global default object, so the test
    /// takes [`crate::test_support::lock_global_state`], the one lock every
    /// global-touching test shares, rather than a lock local to this module.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::lock_global_state()
    }

    unsafe extern "C" fn indicator(
        _type_: *const c_char,
        _desc: *const c_char,
        _params: *const crate::params::OsslParam,
    ) -> core::ffi::c_int {
        1
    }

    #[test]
    fn the_callback_is_per_context_and_replaceable() {
        let _g = lock();
        let a = OSSL_LIB_CTX_new();
        let b = OSSL_LIB_CTX_new();
        assert!(!a.is_null() && !b.is_null());
        let mut got: Option<OsslIndicatorCallback> = None;
        // SAFETY: both contexts are live and the out-pointer is writable.
        unsafe {
            OSSL_INDICATOR_get_callback(a, core::ptr::addr_of_mut!(got));
            assert!(got.is_none());

            OSSL_INDICATOR_set_callback(a, Some(indicator));
            OSSL_INDICATOR_get_callback(a, core::ptr::addr_of_mut!(got));
            assert!(got.is_some_and(|f| f as *const () == indicator as *const ()));

            // `b` is untouched.
            OSSL_INDICATOR_get_callback(b, core::ptr::addr_of_mut!(got));
            assert!(got.is_none());

            // A NULL callback removes it, and a NULL out-pointer is skipped.
            OSSL_INDICATOR_set_callback(a, None);
            OSSL_INDICATOR_get_callback(a, core::ptr::addr_of_mut!(got));
            assert!(got.is_none());
            OSSL_INDICATOR_get_callback(a, core::ptr::null_mut());

            // A NULL context reads the default context's slot.
            let previous = OSSL_LIB_CTX_set0_default(a);
            OSSL_INDICATOR_set_callback(core::ptr::null_mut(), Some(indicator));
            OSSL_INDICATOR_get_callback(core::ptr::null_mut(), core::ptr::addr_of_mut!(got));
            assert!(got.is_some_and(|f| f as *const () == indicator as *const ()));
            OSSL_INDICATOR_set_callback(core::ptr::null_mut(), None);
            OSSL_LIB_CTX_set0_default(previous);

            OSSL_LIB_CTX_free(b);
            OSSL_LIB_CTX_free(a);
        }
    }
}
