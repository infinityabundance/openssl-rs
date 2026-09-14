//! FFI boundary: the invariant that no Rust panic may unwind into C.
//!
//! `docs/RELEASE_GATES.md` §6 and `docs/UNSAFE.md` §3 make this a hard rule:
//! every exported `extern "C"` function establishes an unwind boundary or
//! otherwise guarantees non-unwinding behaviour.
//!
//! ## The invariant is absolute
//!
//! [`guard_ffi`] **always** catches and **never** resumes. Its behaviour does not
//! depend on `debug_assertions`, on the build profile, on an environment
//! variable, or on whether a test is running. That is deliberate:
//!
//! > A boundary whose unwind behaviour varies by configuration is not a boundary.
//!
//! An earlier design resumed the panic in debug builds so that a defect would
//! fail tests loudly. That is a good property to want and a bad way to get it: it
//! meant the control-flow edge "unwind into C" existed in one configuration and
//! not another, so the invariant held only where it was least needed. The edge is
//! now absent from every configuration.
//!
//! ## Getting loud failures without a conditional boundary
//!
//! Instead of propagating, the boundary:
//!
//! * increments a process-wide counter ([`panics_caught`]) that tests assert on;
//! * writes a fixed diagnostic to `stderr` (a write, never an unwind).
//!
//! Tests therefore still fail loudly — they assert that the counter moved and the
//! documented failure value was returned — while the ABI boundary itself is
//! unconditional.
//!
//! When the error subsystem exists (Phase 3), the boundary will additionally
//! push onto the thread-local `ERR` queue, which is what an OpenSSL caller
//! expects to find after a failure. Until then it reports and returns.
//!
//! ## Residual: the panic payload is dropped
//!
//! The payload is not surfaced, because `std::panic::PanicHookInfo` payloads are
//! not ABI-stable and cannot cross into C. Until Phase 3 provides an `ERR`
//! channel, the diagnostic names the condition but not the payload. This is
//! recorded as an obligation rather than hidden; see
//! `forensics/atlas/phase1-completeness.json`.

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

static PANICS_CAUGHT: AtomicUsize = AtomicUsize::new(0);

const PANIC_DIAGNOSTIC: &[u8] =
    b"openssl-rs: panic caught at the FFI boundary (defect); returning the documented failure value\n";

/// Run `f` across an FFI boundary, returning `on_panic` if it panics.
///
/// This is the **only** sanctioned way to call fallible Rust from an exported
/// `extern "C"` function:
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn SOME_OpenSSL_function(arg: *mut Foo) -> c_int {
///     guard_ffi(-1, || {
///         // ... may panic; must never unwind into C ...
///         0
///     })
/// }
/// ```
///
/// The closure is not required to be `UnwindSafe`. This is deliberate and sound
/// here: an FFI entry point makes no promise that its *state* is consistent after
/// a panic — it promises only not to unwind. State left inconsistent by a
/// panicking FFI call is itself the defect to fix, not something this boundary
/// can repair.
#[inline]
pub fn guard_ffi<T, F>(on_panic: T, f: F) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_payload) => {
            // The payload is dropped deliberately: it is not ABI-stable and
            // cannot cross into C. Phase 3 will surface it through ERR.
            PANICS_CAUGHT.fetch_add(1, Ordering::Relaxed);
            let _ = std::io::stderr().write_all(PANIC_DIAGNOSTIC);
            on_panic
        }
    }
}

/// Number of panics caught at the FFI boundary since process start.
///
/// This exists so that tests can prove the boundary actually caught a panic
/// rather than merely returning a default, without the boundary having to
/// change behaviour for the test's benefit.
pub fn panics_caught() -> usize {
    PANICS_CAUGHT.load(Ordering::Relaxed)
}

/// Rust-only helper: propagate a panic instead of catching it.
///
/// **Never call this from an `extern "C"` function.** It exists so that tests of
/// *Rust* call paths can observe the original panic payload, which
/// [`guard_ffi`] deliberately discards. Test-only by construction.
#[cfg(test)]
pub(crate) fn propagate_for_test<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(test)]
// `unwrap_used` is denied crate-wide for product code, where it is a real hazard
// on the FFI path. In tests an `unwrap()` that fails is the desired loud
// failure, so the lint is allowed here rather than weakened globally.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Serialises the tests that read or reset the process-wide counter.
    static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn returns_value_when_no_panic() {
        assert_eq!(guard_ffi(-1, || 42), 42);
    }

    #[test]
    #[allow(clippy::panic)] // deliberately provoking a panic on the FFI path
    fn boundary_catches_and_returns_the_documented_failure_value() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        let before = panics_caught();
        // The critical assertion: this call RETURNS. If the boundary resumed,
        // this line would unwind and the test would fail.
        let value = guard_ffi(-1, || panic!("boom"));
        assert_eq!(value, -1, "the documented failure value must be returned");
        assert_eq!(
            panics_caught(),
            before + 1,
            "the boundary must record that it caught a panic"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn boundary_neutralises_the_panic_in_every_configuration() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        // Directly encode the invariant: catching happens, and the panic does
        // NOT escape this call, regardless of build configuration.
        let outer = std::panic::catch_unwind(|| guard_ffi(0, || panic!("boom")));
        assert!(outer.is_ok(), "guard_ffi must never let a panic escape");
        assert_eq!(outer.unwrap(), 0);
    }

    #[test]
    #[allow(clippy::panic)]
    fn test_helper_still_propagates_for_rust_call_paths() {
        // The test-only helper exists precisely so payload-level assertions
        // remain possible without weakening the ABI boundary.
        let result = std::panic::catch_unwind(|| propagate_for_test(|| panic!("boom")));
        assert!(result.is_err());
    }
}
