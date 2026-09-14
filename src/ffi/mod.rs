//! FFI boundary: the contract that no Rust panic may unwind into C.
//!
//! `docs/RELEASE_GATES.md` §6 and `docs/UNSAFE.md` §3 make this a hard rule:
//! every exported `extern "C"` function must establish an unwind boundary or
//! otherwise guarantee non-unwinding behaviour. This module provides the single
//! shared implementation of that boundary so it cannot be forgotten or
//! re-implemented inconsistently per subsystem.
//!
//! ## Panic policy
//!
//! A panic on the FFI path is a defect. The boundary does not hide it:
//!
//! * in **test and debug** builds the panic is re-raised after the boundary is
//!   established, so tests fail loudly rather than observing a default value;
//! * in **release** builds the panic is caught and the function's documented
//!   failure value is returned, because unwinding into C is undefined and
//!   aborting a caller's process is worse than a documented error return.
//!
//! Recording the defect in the OpenSSL error queue is Phase 3 work (the `ERR`
//! subsystem does not exist yet). Until then the boundary returns the failure
//! value and, in tests, panics — so the defect cannot pass unnoticed.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `f` across an FFI boundary, returning `on_panic` if it panics.
///
/// Call this from every `extern "C"` entry point that can panic.
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn SOME_OpenSSL_function(arg: *mut Foo) -> c_int {
///     guard_ffi(-1, || {
///         // ... may panic; must not unwind into C ...
///         0
///     })
/// }
/// ```
///
/// The closure is not required to be `UnwindSafe`; this is deliberate and sound
/// here because an FFI entry point makes no promise that its state is consistent
/// after a panic — it only promises not to unwind. State left inconsistent by a
/// panicking FFI call is itself a defect to be fixed, not something this
/// boundary can repair.
#[inline]
pub fn guard_ffi<T, F>(on_panic: T, f: F) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => handle_panic(payload, on_panic),
    }
}

/// Handle a caught panic according to the documented policy.
///
/// Split out so the policy lives in one place and can be reasoned about
/// directly. `cfg!` is used rather than `#[cfg]` so both branches are type
/// checked; the constant branch is eliminated by the optimiser.
#[cold]
fn handle_panic<T>(payload: Box<dyn std::any::Any + Send>, on_panic: T) -> T {
    if cfg!(debug_assertions) {
        // Test/debug builds are never the shipped FFI artifact. Propagate the
        // original panic unchanged (rather than replacing it with a message) so
        // that a defect on the FFI path fails tests with its true origin.
        std::panic::resume_unwind(payload);
    }

    // Release builds: return the caller's documented failure value.
    let _ = payload;
    on_panic
}

#[cfg(test)]
mod tests {
    use super::guard_ffi;

    #[test]
    fn returns_value_when_no_panic() {
        assert_eq!(guard_ffi(-1, || 42), 42);
    }

    #[test]
    #[allow(clippy::panic)] // deliberately provoking a panic on the FFI path
    fn panic_on_ffi_path_is_observable_not_swallowed() {
        // Debug builds re-raise, so an outer catch observes the panic. The
        // property under test is that the boundary never silently converts a
        // defect into a plausible return value in test builds.
        let result = std::panic::catch_unwind(|| guard_ffi(-1, || panic!("boom")));
        assert!(result.is_err(), "panic must be observable, not swallowed");
    }
}
