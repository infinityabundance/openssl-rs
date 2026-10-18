//! Exhaustive, test-only state machine for the `OwnedStr` release rules (OB-2).
//!
//! The model mirrors the ownership transitions of `runtime::owned_str::OwnedStr`
//! and is deliberately independent of the implementation's pointer operations.
//! States are `Absent` (`adopt(NULL)` answered `None`), `Null` (a nullable adopt
//! of NULL), `Owned`, `Released`, and `Transferred`; the operations are the two
//! adoption kinds, `into_raw`, and `Drop`.
//!
//! The exploration is bounded: four adoption starts × every operation sequence
//! of length `0..=4` over `{into_raw, Drop}` (31 sequences, 124 traces, 392
//! transitions). It does not model the
//! allocator, pointer provenance, concurrency, or memory safety. The production
//! correspondence tests at the bottom observe the release `Drop` selected via a
//! test-only thread-local probe and compare it with the modelled transition.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::Cell;
use core::ffi::CStr;
use core::ptr;

use super::drop_probe;
use super::OwnedStr;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::mem_coords::SeamFile;

const FILE: &CStr = c"test/owned_str_model.rs";

/// Length bound for the exhaustive operation sequences.
const MAX_STEPS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handle {
    /// `adopt(NULL)` answered `None`: no handle exists.
    Absent,
    /// `adopt_nullable(NULL)`: a live handle whose pointer is NULL.
    Null,
    /// `adopt(non-NULL)`: a live handle owning one seam block.
    Owned,
    /// `Drop` ran and the handle is gone.
    Released,
    /// `into_raw` handed the pointer away and the handle is gone.
    Transferred,
}

/// What the handle was adopted from. Needed to distinguish a real block release
/// from the authority's no-op `free(NULL)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Absent,
    Null,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    handle: Handle,
    origin: Origin,
    /// Releases of a real seam block.
    releases: u32,
    /// `CRYPTO_free(NULL)` calls; never a real release.
    noop_releases: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    Null,
    Block,
    NullableNull,
    NullableBlock,
}

const STARTS: [Start; 4] = [
    Start::Null,
    Start::Block,
    Start::NullableNull,
    Start::NullableBlock,
];

impl Start {
    fn state(self) -> State {
        match self {
            Start::Null => State {
                handle: Handle::Absent,
                origin: Origin::Absent,
                releases: 0,
                noop_releases: 0,
            },
            Start::Block => State {
                handle: Handle::Owned,
                origin: Origin::Block,
                releases: 0,
                noop_releases: 0,
            },
            Start::NullableNull => State {
                handle: Handle::Null,
                origin: Origin::Null,
                releases: 0,
                noop_releases: 0,
            },
            Start::NullableBlock => State {
                handle: Handle::Owned,
                origin: Origin::Block,
                releases: 0,
                noop_releases: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    IntoRaw,
    Drop,
}

const OPS: [Op; 2] = [Op::IntoRaw, Op::Drop];

/// The real rules and the three negative-control mutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    Real,
    /// `Drop` releases the same block twice.
    DoubleRelease,
    /// `into_raw` releases instead of transferring.
    IntoRawReleases,
    /// A NULL handle's `free(NULL)` is counted as a real block release.
    NullReleaseCounted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Violation {
    /// More than one real release of the same handle.
    MultipleReleases,
    /// The ownership transfer released the block.
    IntoRawReleased,
    /// `free(NULL)` was counted as a real release.
    NullReleaseCounted,
}

#[derive(Default)]
struct Report {
    traces: usize,
    steps: usize,
    multiple_releases: usize,
    into_raw_released: usize,
    null_release_counted: usize,
}

impl Report {
    fn record(&mut self, violation: Violation) {
        match violation {
            Violation::MultipleReleases => self.multiple_releases += 1,
            Violation::IntoRawReleased => self.into_raw_released += 1,
            Violation::NullReleaseCounted => self.null_release_counted += 1,
        }
    }

    fn count(&self, violation: Violation) -> usize {
        match violation {
            Violation::MultipleReleases => self.multiple_releases,
            Violation::IntoRawReleased => self.into_raw_released,
            Violation::NullReleaseCounted => self.null_release_counted,
        }
    }

    fn total(&self) -> usize {
        self.multiple_releases + self.into_raw_released + self.null_release_counted
    }
}

/// Check the invariants that must hold after every transition.
fn check(state: &State, report: &mut Report) {
    if state.releases > 1 {
        report.record(Violation::MultipleReleases);
    }
    if state.handle == Handle::Transferred && state.releases != 0 {
        report.record(Violation::IntoRawReleased);
    }
    if state.origin == Origin::Null && state.handle == Handle::Released && state.releases != 0 {
        report.record(Violation::NullReleaseCounted);
    }
}

/// Apply one operation. Operations on a consumed handle are no-ops: Rust's move
/// semantics make them unreachable in production, and the model must not invent
/// a release for a handle that no longer exists.
fn step(state: State, op: Op, proto: Proto, report: &mut Report) -> State {
    report.steps += 1;
    let mut next = state;

    match (op, state.handle) {
        (Op::IntoRaw, Handle::Null | Handle::Owned) => {
            next.handle = Handle::Transferred;
            if proto == Proto::IntoRawReleases {
                next.releases += 1;
            }
        }
        (Op::Drop, Handle::Null) => {
            next.handle = Handle::Released;
            if proto == Proto::NullReleaseCounted {
                next.releases += 1;
            } else {
                next.noop_releases += 1;
            }
        }
        (Op::Drop, Handle::Owned) => {
            next.handle = Handle::Released;
            next.releases += if proto == Proto::DoubleRelease { 2 } else { 1 };
        }
        // `Absent` has no handle; `Released`/`Transferred` are consumed.
        _ => {}
    }

    check(&next, report);
    next
}

/// Every operation sequence of length `0..=MAX_STEPS`, each exactly once.
fn op_sequences() -> Vec<Vec<Op>> {
    let mut out = Vec::new();
    let mut frontier = vec![Vec::new()];
    for _ in 0..=MAX_STEPS {
        out.extend(frontier.iter().cloned());
        let mut next = Vec::new();
        for sequence in &frontier {
            for op in OPS {
                let mut extended = sequence.clone();
                extended.push(op);
                next.push(extended);
            }
        }
        frontier = next;
    }
    out
}

fn run_trace(start: Start, sequence: &[Op], proto: Proto, report: &mut Report) -> State {
    report.traces += 1;
    let mut state = start.state();
    check(&state, report);
    for &op in sequence {
        state = step(state, op, proto, report);
    }
    state
}

fn run_all(proto: Proto) -> Report {
    let mut report = Report::default();
    for start in STARTS {
        for sequence in op_sequences() {
            run_trace(start, &sequence, proto, &mut report);
        }
    }
    report
}

#[test]
fn exhaustive_real_rules_satisfy_every_invariant() {
    let report = run_all(Proto::Real);
    assert!(report.traces > 0, "the harness generated no traces");
    assert!(report.steps > 0, "the harness explored no transition");
    assert_eq!(
        report.total(),
        0,
        "the real rules violated an invariant over {} traces / {} steps",
        report.traces,
        report.steps
    );
    println!(
        "OB-2 model (Real): {} traces, {} steps",
        report.traces, report.steps
    );
}

#[test]
fn real_rules_never_release_after_transfer_or_twice() {
    let mut report = Report::default();
    for start in [Start::Block, Start::NullableBlock] {
        let after_transfer = run_trace(
            start,
            &[Op::IntoRaw, Op::Drop, Op::Drop],
            Proto::Real,
            &mut report,
        );
        assert_eq!(after_transfer.handle, Handle::Transferred);
        assert_eq!(
            after_transfer.releases, 0,
            "into_raw must transfer exactly once with no release"
        );

        let after_drop = run_trace(start, &[Op::Drop, Op::Drop], Proto::Real, &mut report);
        assert_eq!(after_drop.handle, Handle::Released);
        assert_eq!(
            after_drop.releases, 1,
            "Drop must release exactly once, never twice"
        );
    }
    assert_eq!(report.total(), 0);
}

#[test]
fn mutant_double_release_is_detected() {
    let report = run_all(Proto::DoubleRelease);
    assert!(
        report.count(Violation::MultipleReleases) > 0,
        "a double release must be detected: {:?}",
        (
            report.multiple_releases,
            report.into_raw_released,
            report.null_release_counted
        )
    );
}

#[test]
fn mutant_into_raw_release_is_detected() {
    let report = run_all(Proto::IntoRawReleases);
    assert!(
        report.count(Violation::IntoRawReleased) > 0,
        "an into_raw that releases must be detected: {:?}",
        (
            report.multiple_releases,
            report.into_raw_released,
            report.null_release_counted
        )
    );
}

#[test]
fn mutant_null_release_counting_is_detected() {
    let report = run_all(Proto::NullReleaseCounted);
    assert!(
        report.count(Violation::NullReleaseCounted) > 0,
        "counting free(NULL) as a real release must be detected: {:?}",
        (
            report.multiple_releases,
            report.into_raw_released,
            report.null_release_counted
        )
    );
}

fn take_probe() -> Option<drop_probe::Call> {
    drop_probe::LAST.with(Cell::take)
}

fn clear_probe() {
    drop_probe::LAST.with(|last| last.set(None));
}

#[test]
fn production_adopt_null_matches_the_model() {
    let state = Start::Null.state();
    assert_eq!(state.handle, Handle::Absent);
    assert_eq!(state.releases, 0);

    // SAFETY: NULL is explicitly permitted by the adoption contract.
    let owned = unsafe { OwnedStr::adopt(ptr::null_mut(), SeamFile::new(FILE), 1) };
    assert!(owned.is_none(), "adopt(NULL) must answer None");
}

#[test]
fn production_nullable_adopt_null_matches_the_model() {
    clear_probe();
    // SAFETY: NULL is explicitly permitted by the nullable adoption contract.
    let owned = unsafe { OwnedStr::adopt_nullable(ptr::null_mut(), SeamFile::new(FILE), 2) };
    assert!(owned.as_ptr().is_null());
    drop(owned);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call { null: true }),
        "the nullable-NULL handle's Drop is one free(NULL)"
    );

    let mut report = Report::default();
    let state = run_trace(Start::NullableNull, &[Op::Drop], Proto::Real, &mut report);
    assert_eq!(state.handle, Handle::Released);
    assert_eq!(state.releases, 0, "free(NULL) is not a real release");
    assert_eq!(state.noop_releases, 1);
    assert_eq!(report.total(), 0);
}

#[test]
fn production_non_null_adoption_and_drop_match_the_model() {
    // SAFETY: the literal is NUL-terminated and the seam answers a fresh block
    // owned by this frame.
    let raw = unsafe { CRYPTO_strdup(c"owned-str-model".as_ptr(), FILE.as_ptr(), 3) };
    assert!(!raw.is_null(), "the seam must duplicate the literal");
    // SAFETY: `raw` is the fresh seam block just allocated; no other owner will
    // release it.
    let owned = unsafe { OwnedStr::adopt(raw, SeamFile::new(FILE), 4) };
    let Some(owned) = owned else { return };
    assert!(!owned.as_ptr().is_null());

    clear_probe();
    drop(owned);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call { null: false }),
        "a non-NULL handle's Drop is one real release"
    );

    let mut report = Report::default();
    let state = run_trace(Start::Block, &[Op::Drop], Proto::Real, &mut report);
    assert_eq!(state.handle, Handle::Released);
    assert_eq!(state.releases, 1);
    assert_eq!(report.total(), 0);
}

#[test]
fn production_into_raw_matches_the_model() {
    // SAFETY: the literal is NUL-terminated and the seam answers a fresh block
    // owned by this frame.
    let raw = unsafe { CRYPTO_strdup(c"owned-str-transfer".as_ptr(), FILE.as_ptr(), 5) };
    assert!(!raw.is_null(), "the seam must duplicate the literal");
    // SAFETY: `raw` is the fresh seam block just allocated; no other owner will
    // release it.
    let owned = unsafe { OwnedStr::adopt(raw, SeamFile::new(FILE), 6) };
    let Some(owned) = owned else { return };

    clear_probe();
    let raw = owned.into_raw();
    assert!(!raw.is_null());
    assert_eq!(take_probe(), None, "into_raw must suppress Drop");

    let mut report = Report::default();
    let state = run_trace(Start::Block, &[Op::IntoRaw], Proto::Real, &mut report);
    assert_eq!(state.handle, Handle::Transferred);
    assert_eq!(state.releases, 0);
    assert_eq!(report.total(), 0);

    // SAFETY: `raw` is the whole block allocated above and is released here
    // exactly once; no `OwnedStr` still owns it.
    unsafe { CRYPTO_free(raw.cast(), FILE.as_ptr(), 6) };
}
