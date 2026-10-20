//! Test-only observation of the release arm and coordinates an owned block selects.
//!
//! The campaign has five distinct `OwnedBlock` families whose releases differ in the
//! destructive arm (plain `CRYPTO_free` vs `CRYPTO_clear_free`) and in the
//! `(file, line)` coordinates (per-instance, module constant, or `(NULL, 0)`). A
//! later edit that silently changes one is exactly the D1-style drift this probe
//! makes detectable: each family records the arm and coordinates it is about to use,
//! and the family's regression test asserts the recorded values.
//!
//! Thread-local, so concurrent tests cannot see each other's records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::Cell;
use core::ffi::{c_char, c_int};

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
    pub(crate) file: *const c_char,
    pub(crate) line: c_int,
}

thread_local! {
    static LAST: Cell<Option<Call>> = const { Cell::new(None) };
}

/// Record the release `arm`/`file`/`line` a family is about to perform.
pub(crate) fn record(arm: Arm, file: *const c_char, line: c_int) {
    LAST.with(|last| {
        last.set(Some(Call { arm, file, line }));
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
