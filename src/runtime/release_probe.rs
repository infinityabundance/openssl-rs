//! Test-only observation of the release arm, coordinates and address an owned block frees.
//!
//! The campaign has several `OwnedBlock`/`OwnedCtx`/`RawCtx` families whose releases differ in
//! the destructive arm (plain `CRYPTO_free` vs `CRYPTO_clear_free`) and in the `(file, line)`
//! coordinates (per-instance, module constant, or `(NULL, 0)`). A later edit that silently
//! changes one is exactly the D1-style drift this probe makes detectable: each family records the
//! arm, the address it is about to release and the coordinates it uses, and the family's
//! regression test asserts the recorded values.
//!
//! The address is recorded so a test can assert a *specific* block was released exactly once,
//! rather than counting every release in a window: an owner that released a neighbour's block, or
//! released its own twice, would not satisfy "this address, once". [`LAST`] holds one record and
//! [`take`] consumes it, so a second `take` observing `None` is evidence that the drop path does
//! not release again.
//!
//! Thread-local, so concurrent tests cannot see each other's records. Never compiled into a
//! non-test build.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::Cell;
use core::ffi::{c_char, c_int, c_void};

/// The destructive arm a block's `Drop` selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arm {
    /// A plain `CRYPTO_free(ptr, file, line)`.
    Plain,
    /// A `CRYPTO_clear_free(ptr, len, file, line)` over `len` bytes.
    Cleansed { len: usize },
}

/// One recorded release.
#[derive(Clone, Copy)]
pub(crate) struct Call {
    pub(crate) arm: Arm,
    /// The address the family is about to release (`NULL` for the seam's empty-block release).
    pub(crate) ptr: *mut c_void,
    pub(crate) file: *const c_char,
    pub(crate) line: c_int,
}

thread_local! {
    static LAST: Cell<Option<Call>> = const { Cell::new(None) };
}

/// Record the release `arm`/`ptr`/`file`/`line` a family is about to perform.
pub(crate) fn record(arm: Arm, ptr: *mut c_void, file: *const c_char, line: c_int) {
    LAST.with(|last| {
        last.set(Some(Call {
            arm,
            ptr,
            file,
            line,
        }));
    });
}

/// Take the last record, or `None` if no family has recorded since the last take.
pub(crate) fn take() -> Option<Call> {
    LAST.with(Cell::take)
}

/// Forget any previous record.
pub(crate) fn clear() {
    LAST.with(|last| last.set(None));
}
