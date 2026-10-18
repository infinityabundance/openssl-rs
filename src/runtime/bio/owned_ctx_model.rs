//! Exhaustive, test-only state machine for the OB-3 transition rules of
//! `runtime::bio::owned::{OwnedCtx, RawCtx}`.
//!
//! This is **not** the implementation. It is an independently written transition
//! system that mirrors the four states the owner types expose and the six
//! invariants they claim:
//!
//! * the states are `Raw` (allocated, not yet a valid `T`), `Owned` (a valid
//!   `T`), `Transferred` (the raw pointer was given to the C caller) and
//!   `Released` (the block has been released);
//! * acquisition (`CRYPTO_malloc`/`CRYPTO_zalloc`) is the start of a trace and
//!   produces `Raw`; `assume_init` is the only `Raw -> Owned` transition;
//!   `into_raw` is the only transition to `Transferred`; `from_raw` is the only
//!   `Transferred -> Owned` transition; `Drop` is the only transition to
//!   `Released`.
//!
//! The invariants checked are:
//!
//! (a) the full destructor (`destroy_body` **and** the block release) runs only
//!     from `Owned`;
//! (b) `RawCtx`'s `Drop` releases the block alone and never runs
//!     `destroy_body`;
//! (c) every terminal path that performs a `Drop` has exactly one block
//!     release;
//! (d) `into_raw` suppresses `Drop`, and a later `from_raw` reclaim is the only
//!     matching release;
//! (e) no transition is admitted from `Released`;
//! (f) `assume_init` cannot be reached twice.
//!
//! A `Transferred` state with no reclaim is the exported-ownership boundary: the
//! C caller owns the block and a leak there is the application's, not a second
//! release. The model therefore requires the reclaim's release to be the single
//! one, but does not require every finite prefix to end in `Released`.
//!
//! The exploration is finite: two acquisition origins times the product state
//! (`Phase` x bounded `destroys`/`releases`/`assume_inits` counters). The model
//! abstracts pointers, allocator identity, provenance, concurrency and memory
//! safety; it is evidence about the transition rules, not a proof about the
//! implementation. The correspondence tests at the bottom connect it to the
//! production `Drop`/`into_raw`/`assume_init` bodies.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use core::cell::Cell;
use core::ptr;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{drop_probe, CtxDestroy, OwnedCtx, RawCtx};

// -------------------------------------------------------------------------------------------
// Model
// -------------------------------------------------------------------------------------------

/// The acquisition that produced the block. Both authorities end in `Raw`; the
/// origin is carried so a trace cannot silently mix them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Origin {
    Malloc,
    Zalloc,
}

/// The four states named by the OB-3 model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Raw,
    Owned,
    Transferred,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    AssumeInit,
    IntoRaw,
    FromRaw,
    Drop,
}

const OPS: [Op; 4] = [Op::AssumeInit, Op::IntoRaw, Op::FromRaw, Op::Drop];

/// The real rules and the four negative-control mutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Real,
    /// (i) `RawCtx::drop` runs `destroy_body`.
    DestroyFromRaw,
    /// (ii) `Drop` releases the block twice.
    DoubleBlockRelease,
    /// (iii) `from_raw` reclaims a block that was never transferred (including
    /// one already released).
    FromRawUntransferred,
    /// (iv) `into_raw` releases instead of transferring.
    IntoRawReleases,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Violation {
    /// (a)/(b): the destructor body ran from `Raw`.
    DestructorFromRaw,
    /// (c): a `Drop` terminal path released no block.
    MissingBlockRelease,
    /// (c): a `Drop` terminal path released the block more than once.
    MultipleReleases,
    /// (d): `into_raw` released instead of suppressing `Drop`.
    IntoRawReleased,
    /// (d)/(iii): `from_raw` started from a state other than `Transferred`.
    FromRawNotTransferred,
    /// (f): a second `assume_init` was admitted.
    AssumeInitTwice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    origin: Origin,
    phase: Phase,
    /// Bounded so the mutant explorations stay finite; the invariants only
    /// distinguish 0, 1 and "more than one".
    destroys: u8,
    releases: u8,
    assume_inits: u8,
}

impl State {
    fn start(origin: Origin) -> Self {
        State {
            origin,
            phase: Phase::Raw,
            destroys: 0,
            releases: 0,
            assume_inits: 0,
        }
    }
}

fn bump(value: u8) -> u8 {
    value.saturating_add(1).min(2)
}

#[derive(Default)]
struct Report {
    starts: usize,
    transitions: usize,
    /// Operations the real rules refused (for example `Drop` in `Transferred`,
    /// or any operation in `Released`). A refusal is the (e) transition rule,
    /// not a violation.
    rejected: usize,
    violations: BTreeMap<Violation, usize>,
}

impl Report {
    fn record(&mut self, violation: Violation) {
        *self.violations.entry(violation).or_insert(0) += 1;
    }

    fn count(&self, violation: Violation) -> usize {
        *self.violations.get(&violation).unwrap_or(&0)
    }
}

/// One transition. `None` means the real rules refuse the operation from this
/// state; the refusal is counted, not treated as a violation.
fn step(state: State, op: Op, proto: Proto, report: &mut Report) -> Option<State> {
    report.transitions += 1;
    let mut next = state;

    if state.phase == Phase::Released {
        // (e) No transition is admitted from `Released`. Mutant (iii) is the one
        // rule that can resurrect a released block; it is recorded as the
        // defect it models rather than as a normal transition.
        if proto == Proto::FromRawUntransferred && op == Op::FromRaw {
            report.record(Violation::FromRawNotTransferred);
            next.phase = Phase::Owned;
            return Some(next);
        }
        report.rejected += 1;
        return None;
    }

    match op {
        Op::AssumeInit => {
            // (f) The only `Raw -> Owned` transition, and only from `Raw`.
            if state.phase != Phase::Raw {
                report.rejected += 1;
                return None;
            }
            next.assume_inits = bump(next.assume_inits);
            if next.assume_inits > 1 {
                report.record(Violation::AssumeInitTwice);
            }
            next.phase = Phase::Owned;
        }
        Op::IntoRaw => {
            if !matches!(state.phase, Phase::Raw | Phase::Owned) {
                report.rejected += 1;
                return None;
            }
            if proto == Proto::IntoRawReleases {
                next.releases = bump(next.releases);
            }
            // (d) A transfer releases nothing; only the later reclaim's `Drop`
            // may release.
            if next.releases != state.releases {
                report.record(Violation::IntoRawReleased);
            }
            next.phase = Phase::Transferred;
        }
        Op::FromRaw => {
            if state.phase != Phase::Transferred {
                if proto != Proto::FromRawUntransferred {
                    report.rejected += 1;
                    return None;
                }
                report.record(Violation::FromRawNotTransferred);
            }
            next.phase = Phase::Owned;
        }
        Op::Drop => {
            if !matches!(state.phase, Phase::Raw | Phase::Owned) {
                report.rejected += 1;
                return None;
            }
            if state.phase == Phase::Raw {
                // (a)/(b) `RawCtx::drop` never runs the destructor body.
                if proto == Proto::DestroyFromRaw {
                    next.destroys = bump(next.destroys);
                    report.record(Violation::DestructorFromRaw);
                }
            } else {
                next.destroys = bump(next.destroys);
            }
            let delta = if proto == Proto::DoubleBlockRelease {
                2
            } else {
                1
            };
            next.releases = next.releases.saturating_add(delta).min(2);
            next.phase = Phase::Released;
            // (c) A `Drop` terminal path releases exactly one block.
            if next.releases != 1 {
                report.record(if next.releases == 0 {
                    Violation::MissingBlockRelease
                } else {
                    Violation::MultipleReleases
                });
            }
        }
    }

    Some(next)
}

/// A bound on the exploration; reaching it is reported by the tests.
const MAX_TRANSITIONS: usize = 100_000;

fn explore(proto: Proto) -> Report {
    let mut report = Report::default();
    let mut queue = VecDeque::new();
    let mut seen = BTreeSet::new();

    for origin in [Origin::Malloc, Origin::Zalloc] {
        let state = State::start(origin);
        report.starts += 1;
        if seen.insert(state) {
            queue.push_back(state);
        }
    }

    while let Some(state) = queue.pop_front() {
        if report.transitions >= MAX_TRANSITIONS {
            break;
        }
        for op in OPS {
            if report.transitions >= MAX_TRANSITIONS {
                break;
            }
            if let Some(next) = step(state, op, proto, &mut report) {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }

    report
}

// -------------------------------------------------------------------------------------------
// Model checks and negative controls
// -------------------------------------------------------------------------------------------

#[test]
fn exhaustive_real_rules_satisfy_every_invariant() {
    let report = explore(Proto::Real);
    assert_eq!(
        report.starts, 2,
        "both acquisition origins must start a trace"
    );
    assert!(report.transitions > 0, "the harness explored no transition");
    assert!(
        report.violations.is_empty(),
        "the real rules violated {:?} over {} transitions from {} starts",
        report.violations,
        report.transitions,
        report.starts
    );
    println!(
        "OB-3 model (Real): {} starts, {} transitions, {} rejected",
        report.starts, report.transitions, report.rejected
    );
}

#[test]
fn exhaustive_real_rules_stay_inside_the_declared_bound() {
    let report = explore(Proto::Real);
    assert!(
        report.transitions < MAX_TRANSITIONS,
        "the exploration hit the {MAX_TRANSITIONS}-transition bound"
    );
}

#[test]
fn a_released_state_admits_no_transition() {
    // (e) Drive the real rules to `Released`, then attempt every operation.
    let mut report = Report::default();
    let raw = State::start(Origin::Malloc);
    let released = step(raw, Op::Drop, Proto::Real, &mut report)
        .expect("RawCtx::drop is the block-only release");
    assert_eq!(released.phase, Phase::Released);
    assert_eq!(released.releases, 1);
    assert_eq!(released.destroys, 0, "the raw drop must not run the body");

    for op in OPS {
        assert!(
            step(released, op, Proto::Real, &mut report).is_none(),
            "the real rules must refuse {op:?} from Released"
        );
    }
}

#[test]
fn assume_init_is_admitted_only_from_raw() {
    // (f) `assume_init` consumes `RawCtx` and produces `OwnedCtx`; it is not a
    // state `from_raw` can reach again, and the model refuses a second call.
    let mut report = Report::default();
    let raw = State::start(Origin::Zalloc);
    let owned = step(raw, Op::AssumeInit, Proto::Real, &mut report).expect("Raw is admissible");
    assert_eq!(owned.phase, Phase::Owned);
    assert_eq!(owned.assume_inits, 1);
    assert!(
        step(owned, Op::AssumeInit, Proto::Real, &mut report).is_none(),
        "the real rules must refuse a second assume_init"
    );
    assert_eq!(report.count(Violation::AssumeInitTwice), 0);
}

#[test]
fn into_raw_transfers_and_the_reclaim_is_the_matching_release() {
    // (c)/(d) The intended production path: Raw -> Owned -> Transferred ->
    // Owned -> Released releases once, and only at the reclaim's Drop.
    let mut report = Report::default();
    let raw = State::start(Origin::Malloc);
    let owned = step(raw, Op::AssumeInit, Proto::Real, &mut report).expect("Raw -> Owned");
    let transferred =
        step(owned, Op::IntoRaw, Proto::Real, &mut report).expect("Owned -> Transferred");
    assert_eq!(transferred.phase, Phase::Transferred);
    assert_eq!(transferred.releases, 0, "into_raw must not release");
    let reclaimed =
        step(transferred, Op::FromRaw, Proto::Real, &mut report).expect("Transferred -> Owned");
    assert_eq!(reclaimed.phase, Phase::Owned);
    assert_eq!(reclaimed.releases, 0);
    let released = step(reclaimed, Op::Drop, Proto::Real, &mut report).expect("Owned -> Released");
    assert_eq!(released.releases, 1);
    assert_eq!(released.destroys, 1);
    assert!(report.violations.is_empty());
}

#[test]
fn mutant_destroy_body_from_raw_is_detected() {
    let report = explore(Proto::DestroyFromRaw);
    println!(
        "OB-3 model (mutant i): {} transitions, {} DestructorFromRaw",
        report.transitions,
        report.count(Violation::DestructorFromRaw)
    );
    assert!(
        report.count(Violation::DestructorFromRaw) > 0,
        "mutant (i): a destructor body from Raw must be reported"
    );
}

#[test]
fn mutant_double_block_release_is_detected() {
    let report = explore(Proto::DoubleBlockRelease);
    println!(
        "OB-3 model (mutant ii): {} transitions, {} MultipleReleases",
        report.transitions,
        report.count(Violation::MultipleReleases)
    );
    assert!(
        report.count(Violation::MultipleReleases) > 0,
        "mutant (ii): a double block release must be reported"
    );
}

#[test]
fn mutant_from_raw_without_transfer_is_detected() {
    let report = explore(Proto::FromRawUntransferred);
    println!(
        "OB-3 model (mutant iii): {} transitions, {} FromRawNotTransferred",
        report.transitions,
        report.count(Violation::FromRawNotTransferred)
    );
    assert!(
        report.count(Violation::FromRawNotTransferred) > 0,
        "mutant (iii): reclaiming a non-transferred block must be reported"
    );
}

#[test]
fn mutant_into_raw_release_is_detected() {
    let report = explore(Proto::IntoRawReleases);
    println!(
        "OB-3 model (mutant iv): {} transitions, {} IntoRawReleased",
        report.transitions,
        report.count(Violation::IntoRawReleased)
    );
    assert!(
        report.count(Violation::IntoRawReleased) > 0,
        "mutant (iv): a releasing into_raw must be reported"
    );
}

// -------------------------------------------------------------------------------------------
// Production correspondence
// -------------------------------------------------------------------------------------------

thread_local! {
    /// `destroy_body` invocations observed on this thread. Thread-local so the
    /// correspondence tests cannot see a parallel test's drops.
    static DESTROYS: Cell<usize> = const { Cell::new(0) };
}

/// A test-only context whose destructor records its own call and releases
/// nothing. It holds a plain integer, so an all-zero block is a valid value and
/// the destructor is sound on it (this is the model's `T: CtxDestroy`
/// obligation (b), discharged here for the probe only).
#[repr(C)]
struct ProbeCtx {
    marker: usize,
}

// SAFETY: (a) `destroy_body` releases no member (the block holds one integer)
// and never releases the enclosing block; it only records its call.
// (b) an all-zero `ProbeCtx` is a valid value for which `destroy_body` is sound.
unsafe impl CtxDestroy for ProbeCtx {
    unsafe fn destroy_body(_ptr: *mut ProbeCtx) {
        DESTROYS.with(|n| n.set(n.get() + 1));
    }
}

fn destroys() -> usize {
    DESTROYS.with(Cell::get)
}

fn reset_drop_probe() {
    drop_probe::LAST.with(|last| last.set(None));
}

fn last_drop() -> Option<drop_probe::Call> {
    drop_probe::LAST.with(Cell::get)
}

#[test]
fn acquisition_starts_raw_and_raw_drop_releases_the_block_alone() {
    // `malloc`/`zalloc` -> Raw; `RawCtx::drop` -> Released (block only).
    for raw in [
        RawCtx::<ProbeCtx>::malloc().expect("malloc must answer a block"),
        RawCtx::<ProbeCtx>::zalloc().expect("zalloc must answer a block"),
    ] {
        reset_drop_probe();
        let before = destroys();
        drop(raw);
        assert_eq!(last_drop(), Some(drop_probe::Call::Raw));
        assert_eq!(destroys(), before, "RawCtx::drop must not run destroy_body");
    }
}

#[test]
fn assume_init_moves_to_owned_and_drop_runs_the_body_once() {
    // `assume_init` -> Owned; `OwnedCtx::drop` -> body + block release.
    reset_drop_probe();
    let before = destroys();
    let raw = RawCtx::<ProbeCtx>::zalloc().expect("zalloc must answer a block");
    // SAFETY: `ProbeCtx`'s zero state is valid, and `raw` is the sole owner of
    // the block; this is the transition `OwnedCtx::zalloc` performs internally.
    let owned = unsafe { raw.assume_init() };
    drop(owned);
    assert_eq!(last_drop(), Some(drop_probe::Call::Owned));
    assert_eq!(destroys(), before + 1);
}

#[test]
fn raw_into_raw_suppresses_drop_and_from_raw_reclaims_once() {
    // `into_raw` -> Transferred (no Drop); `from_raw` -> Owned; Drop releases.
    reset_drop_probe();
    let before = destroys();
    let raw = RawCtx::<ProbeCtx>::zalloc().expect("zalloc must answer a block");
    let p = raw.into_raw();
    assert!(!p.is_null());
    assert_eq!(
        last_drop(),
        None,
        "RawCtx::into_raw must suppress Drop (obligation (d))"
    );
    assert_eq!(destroys(), before, "into_raw must not run destroy_body");

    // SAFETY: `p` is the live block `raw` gave up and no other owner holds it.
    let owned = unsafe { OwnedCtx::<ProbeCtx>::from_raw(p) }.expect("non-NULL");
    drop(owned);
    assert_eq!(last_drop(), Some(drop_probe::Call::Owned));
    assert_eq!(destroys(), before + 1);
}

#[test]
fn owned_into_raw_suppresses_the_full_destructor() {
    // `OwnedCtx::into_raw` -> Transferred (no body, no release); the reclaim is
    // the only `Drop`.
    reset_drop_probe();
    let before = destroys();
    let owned = OwnedCtx::<ProbeCtx>::zalloc().expect("zalloc must answer a block");
    let p = owned.into_raw();
    assert!(!p.is_null());
    assert_eq!(
        last_drop(),
        None,
        "OwnedCtx::into_raw must suppress the full destructor"
    );
    assert_eq!(destroys(), before);

    // SAFETY: `p` is the live block `owned` gave up and no other owner holds it.
    let reclaimed = unsafe { OwnedCtx::<ProbeCtx>::from_raw(p) }.expect("non-NULL");
    drop(reclaimed);
    assert_eq!(last_drop(), Some(drop_probe::Call::Owned));
    assert_eq!(destroys(), before + 1);
}

#[test]
fn from_raw_null_is_no_owner() {
    // SAFETY: NULL is admitted by `from_raw`'s contract and answers `None`.
    assert!(unsafe { OwnedCtx::<ProbeCtx>::from_raw(ptr::null_mut()) }.is_none());
}
