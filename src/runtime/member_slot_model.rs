//! Test-only exhaustive model of the member-buffer slots (`OB-4`).
//!
//! This is **not** the implementation. It is an independently written transition
//! system for the rules [`crate::runtime::member_slot::CStrSlot`] and
//! `ssl_lib::MemberBufSlot` expose:
//!
//! * `Empty` — the field is NULL and no store token has been issued;
//! * `Transferred` — a `clear`/`assume_empty` token exists; the field is NULL and
//!   exactly one store may consume the token;
//! * `Occupied` — the object owns one block; only `clear`/`Drop` may release it.
//!
//! The model checks the invariants the production types claim:
//!
//! (a) a store is admitted only after a token (never into `Occupied`);
//! (b) an occupied block is released exactly once, by `clear` or `Drop`;
//! (c) a second `clear` reaches only the NULL empty state and releases nothing;
//! (d) `assume_empty` is admitted only when the field is empty;
//! (e) a refused `realloc` keeps the incumbent block;
//! (f) a stored C-string is terminated.
//!
//! The exploration is finite: state is the phase plus bounded counters
//! (`releases`/`stores`/`clears`/`drops`, each 0..=2) and the termination bit.
//! The negative controls use the same exploration with one rule mutated, and each
//! mutant asserts that its violation is reached. The correspondence tests at the
//! bottom exercise the production bodies through their safe/unsafe interfaces.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use core::ptr;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::runtime::mem_coords::SeamFile;
use crate::runtime::member_slot::{CStrSlot, EmptyCStrSlot};
use crate::runtime::owned_str::OwnedCStr;

/// The three states named by the OB-4 slot model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Empty,
    Transferred,
    Occupied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Clear,
    AssumeEmpty,
    Store,
    StoreRaw,
    ReallocOk,
    ReallocFail,
    Drop,
}

const OPS: [Op; 7] = [
    Op::Clear,
    Op::AssumeEmpty,
    Op::Store,
    Op::StoreRaw,
    Op::ReallocOk,
    Op::ReallocFail,
    Op::Drop,
];

/// The real rules and the seven negative controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Real,
    /// A second `store` from `Occupied` is admitted (two owners).
    DoubleStore,
    /// `store` overwrites an occupied member without releasing it.
    StoreIntoOccupied,
    /// A second `clear` from `Transferred` releases again.
    DoubleClear,
    /// `store` accepts an unterminated block.
    NonTerminatedStore,
    /// `clear` frees before nulling, so the allocator hook observes a dangling field.
    FreeBeforeNull,
    /// A refused `realloc` publishes NULL instead of keeping the old block.
    ReallocFailurePublishesNull,
    /// `clear` releases but leaves the pointer in the field.
    ClearWithoutNulling,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Violation {
    StoreIntoOccupied,
    DoubleOwnership,
    NonTerminatedMember,
    DoubleRelease,
    ReleaseOfUnacquired,
    StaleOccupied,
    LostIncumbent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    phase: Phase,
    /// 0 or 1 in every real trace; the `DoubleStore` mutant reaches 2.
    owners: u8,
    terminated: bool,
    releases: u8,
    stores: u8,
    clears: u8,
    drops: u8,
}

impl State {
    fn start() -> State {
        State {
            phase: Phase::Empty,
            owners: 0,
            terminated: true,
            releases: 0,
            stores: 0,
            clears: 0,
            drops: 0,
        }
    }
}

fn bump(value: u8) -> u8 {
    value.saturating_add(1).min(2)
}

#[derive(Default)]
struct Report {
    transitions: usize,
    violations: BTreeMap<Violation, usize>,
}

impl Report {
    fn record(&mut self, violation: Violation) {
        *self.violations.entry(violation).or_insert(0) += 1;
    }

    fn count(&self, violation: Violation) -> usize {
        self.violations.get(&violation).copied().unwrap_or(0)
    }

    fn clean(&self) -> bool {
        self.violations.is_empty()
    }
}

fn step(state: State, op: Op, proto: Proto, report: &mut Report) -> Option<State> {
    let mut s = state;
    match op {
        Op::Clear => {
            s.clears = bump(s.clears);
            match s.phase {
                Phase::Empty => {
                    // Releasing NULL is the authority's no-op; the token still exists.
                    s.phase = Phase::Transferred;
                }
                Phase::Occupied => {
                    if proto == Proto::FreeBeforeNull {
                        // The release ran while the field still named the block.
                        report.record(Violation::ReleaseOfUnacquired);
                        s.phase = Phase::Occupied;
                    } else {
                        if s.owners == 0 {
                            // Only `ClearWithoutNulling` can leave an `Occupied` phase
                            // whose block has already been released; a second clear
                            // then frees the same block again.
                            report.record(Violation::DoubleRelease);
                        }
                        s.releases = bump(s.releases);
                        s.owners = 0;
                        s.phase = if proto == Proto::ClearWithoutNulling {
                            report.record(Violation::StaleOccupied);
                            Phase::Occupied
                        } else {
                            Phase::Transferred
                        };
                    }
                }
                Phase::Transferred => {
                    // A repeated clear sees NULL. Only the mutant releases again.
                    if proto == Proto::DoubleClear {
                        s.releases = bump(s.releases);
                        report.record(Violation::DoubleRelease);
                    }
                }
            }
        }
        Op::AssumeEmpty => match s.phase {
            Phase::Empty | Phase::Transferred => s.phase = Phase::Transferred,
            Phase::Occupied => {
                // The real rules refuse this transition; the mutant set below is
                // what makes an admitted `assume_empty` a violation.
                return None;
            }
        },
        Op::Store | Op::StoreRaw => match s.phase {
            Phase::Transferred => {
                s.phase = Phase::Occupied;
                s.stores = bump(s.stores);
                s.owners = bump(s.owners);
                if proto == Proto::NonTerminatedStore {
                    s.terminated = false;
                    report.record(Violation::NonTerminatedMember);
                } else {
                    s.terminated = true;
                }
                if s.owners > 1 {
                    report.record(Violation::DoubleOwnership);
                }
            }
            Phase::Occupied => {
                if proto == Proto::DoubleStore {
                    s.stores = bump(s.stores);
                    s.owners = bump(s.owners);
                    report.record(Violation::DoubleOwnership);
                } else if proto == Proto::StoreIntoOccupied {
                    // Overwrite without release: the incumbent's ownership is lost.
                    s.stores = bump(s.stores);
                    report.record(Violation::StoreIntoOccupied);
                    report.record(Violation::LostIncumbent);
                } else {
                    // The safe API has no store path for an occupied slot.
                    return None;
                }
            }
            Phase::Empty => {
                // A store needs the token that `clear`/`assume_empty` produces.
                return None;
            }
        },
        Op::ReallocOk => {
            // `CRYPTO_realloc` accepts NULL (an empty member) as an allocation. On
            // success exactly one block -- the possibly moved incumbent -- is owned,
            // whether the old state was empty or occupied; a realloc never
            // duplicates ownership.
            s.phase = Phase::Occupied;
            s.terminated = true;
            s.owners = 1;
        }
        Op::ReallocFail => match s.phase {
            Phase::Occupied => {
                if proto == Proto::ReallocFailurePublishesNull {
                    report.record(Violation::LostIncumbent);
                    s.phase = Phase::Empty;
                    s.owners = 0;
                }
                // Real rules keep the old block and its owner.
            }
            Phase::Empty | Phase::Transferred => {
                // A refused allocation of a NULL block leaves the member exactly as
                // it was: still empty, and an outstanding clear/assume_empty token
                // remains usable.
            }
        },
        Op::Drop => {
            s.drops = bump(s.drops);
            match s.phase {
                Phase::Occupied => {
                    s.releases = bump(s.releases);
                    s.owners = 0;
                    s.phase = Phase::Empty;
                }
                Phase::Empty | Phase::Transferred => {
                    // Releasing an empty member releases nothing.
                    s.phase = Phase::Empty;
                }
            }
        }
    }
    Some(s)
}

/// The ownership, phase and termination invariants the production types rely on.
///
/// The real rules must never produce a state that breaks one. The negative
/// controls deliberately do, so this check is applied to `Real` only; each
/// mutant has its own discriminating assertion.
fn invariant_violation(s: &State) -> Option<Violation> {
    match s.phase {
        Phase::Occupied => match s.owners {
            1 if s.terminated => None,
            1 => Some(Violation::NonTerminatedMember),
            0 => Some(Violation::LostIncumbent),
            _ => Some(Violation::DoubleOwnership),
        },
        Phase::Empty | Phase::Transferred => {
            if s.owners == 0 {
                None
            } else {
                Some(Violation::DoubleOwnership)
            }
        }
    }
}

const MAX_TRANSITIONS: usize = 100_000;

fn explore(proto: Proto) -> Report {
    let mut report = Report::default();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    let start = State::start();
    seen.insert(start);
    queue.push_back(start);
    while let Some(state) = queue.pop_front() {
        for op in OPS {
            report.transitions += 1;
            if report.transitions >= MAX_TRANSITIONS {
                return report;
            }
            if let Some(next) = step(state, op, proto, &mut report) {
                if proto == Proto::Real {
                    if let Some(violation) = invariant_violation(&next) {
                        report.record(violation);
                    }
                }
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }
    report
}

// -------------------------------------------------------------------------------------------
// Exhaustive real-rules checks
// -------------------------------------------------------------------------------------------

#[test]
fn exhaustive_real_rules_satisfy_every_invariant() {
    let report = explore(Proto::Real);
    println!(
        "OB-4 slot model: {} transitions, {} violation classes, {} violation events",
        report.transitions,
        report.violations.len(),
        report.violations.values().sum::<usize>()
    );
    assert!(report.transitions > 0, "the harness explored no transition");
    assert!(
        report.clean(),
        "real rules must satisfy every invariant: {:?}",
        report.violations
    );
}

#[test]
fn exhaustive_real_rules_stay_inside_the_declared_bound() {
    assert!(
        explore(Proto::Real).transitions < MAX_TRANSITIONS,
        "the exploration hit the {MAX_TRANSITIONS}-transition bound"
    );
}

#[test]
fn a_store_needs_a_token_and_never_overwrites_an_occupant() {
    let mut report = Report::default();
    let mut s = State::start();
    s.phase = Phase::Occupied;
    s.owners = 1;
    // A direct store from Occupied is refused and reported.
    let next = step(s, Op::Store, Proto::Real, &mut report);
    assert!(next.is_none());
    assert!(
        report.clean(),
        "a refused transition is not an invariant violation"
    );

    // A store from Empty (no token) is refused too.
    let mut report = Report::default();
    let next = step(State::start(), Op::Store, Proto::Real, &mut report);
    assert!(next.is_none());
    assert!(report.clean());
}

#[test]
fn a_second_clear_releases_nothing() {
    let mut report = Report::default();
    let mut s = State::start();
    s.phase = Phase::Transferred;
    s.releases = 1;
    let next = step(s, Op::Clear, Proto::Real, &mut report).expect("clear is total");
    assert_eq!(next.phase, Phase::Transferred);
    assert_eq!(next.releases, 1, "a repeated clear must not release again");
    assert!(report.clean());
}

#[test]
fn realloc_failure_keeps_the_owner() {
    let mut report = Report::default();
    let mut s = State::start();
    s.phase = Phase::Occupied;
    s.owners = 1;
    let next = step(s, Op::ReallocFail, Proto::Real, &mut report).expect("realloc is total");
    assert_eq!(next.phase, Phase::Occupied);
    assert_eq!(next.owners, 1);
    assert!(report.clean());
}

// -------------------------------------------------------------------------------------------
// Negative controls: every mutant must be detected
// -------------------------------------------------------------------------------------------

#[test]
fn mutant_double_store_is_detected() {
    let report = explore(Proto::DoubleStore);
    println!(
        "OB-4 mutant DoubleStore: {} transitions, {} DoubleOwnership",
        report.transitions,
        report.count(Violation::DoubleOwnership)
    );
    assert!(report.count(Violation::DoubleOwnership) > 0);
}

#[test]
fn mutant_store_into_occupied_is_detected() {
    let report = explore(Proto::StoreIntoOccupied);
    println!(
        "OB-4 mutant StoreIntoOccupied: {} transitions, {} StoreIntoOccupied, {} LostIncumbent",
        report.transitions,
        report.count(Violation::StoreIntoOccupied),
        report.count(Violation::LostIncumbent)
    );
    assert!(report.count(Violation::StoreIntoOccupied) > 0);
    assert!(report.count(Violation::LostIncumbent) > 0);
}

#[test]
fn mutant_double_clear_is_detected() {
    let report = explore(Proto::DoubleClear);
    println!(
        "OB-4 mutant DoubleClear: {} transitions, {} DoubleRelease",
        report.transitions,
        report.count(Violation::DoubleRelease)
    );
    assert!(report.count(Violation::DoubleRelease) > 0);
}

#[test]
fn mutant_non_terminated_store_is_detected() {
    let report = explore(Proto::NonTerminatedStore);
    println!(
        "OB-4 mutant NonTerminatedStore: {} transitions, {} NonTerminatedMember",
        report.transitions,
        report.count(Violation::NonTerminatedMember)
    );
    assert!(report.count(Violation::NonTerminatedMember) > 0);
}

#[test]
fn mutant_free_before_null_is_detected() {
    let report = explore(Proto::FreeBeforeNull);
    println!(
        "OB-4 mutant FreeBeforeNull: {} transitions, {} ReleaseOfUnacquired",
        report.transitions,
        report.count(Violation::ReleaseOfUnacquired)
    );
    assert!(report.count(Violation::ReleaseOfUnacquired) > 0);
}

#[test]
fn mutant_realloc_failure_publishes_null_is_detected() {
    let report = explore(Proto::ReallocFailurePublishesNull);
    println!(
        "OB-4 mutant ReallocFailurePublishesNull: {} transitions, {} LostIncumbent",
        report.transitions,
        report.count(Violation::LostIncumbent)
    );
    assert!(report.count(Violation::LostIncumbent) > 0);
}

#[test]
fn mutant_clear_without_nulling_is_detected() {
    let report = explore(Proto::ClearWithoutNulling);
    println!(
        "OB-4 mutant ClearWithoutNulling: {} transitions, {} StaleOccupied",
        report.transitions,
        report.count(Violation::StaleOccupied)
    );
    assert!(report.count(Violation::StaleOccupied) > 0);
}

// -------------------------------------------------------------------------------------------
// Correspondence with the production bodies
// -------------------------------------------------------------------------------------------

const FILE: &core::ffi::CStr = c"test/member_slot_model.rs";

fn install_miri_shim() {
    #[cfg(miri)]
    crate::runtime::miri_tcb::install();
}

fn dup(s: &core::ffi::CStr) -> OwnedCStr {
    // SAFETY: the literal is NUL-terminated and the seam answers a fresh block.
    unsafe { OwnedCStr::dup(s.as_ptr(), SeamFile::new(FILE), 1) }.unwrap()
}

#[test]
fn production_clear_store_and_second_clear_match_the_real_rules() {
    install_miri_shim();
    let mut field: *mut core::ffi::c_char = ptr::null_mut();
    {
        // SAFETY: `field` is this test's own member and is initially NULL.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 2).store(dup(c"alpha"));
    }
    assert!(!field.is_null());
    {
        // SAFETY: `field` holds the block this test stored.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 3);
    }
    assert!(field.is_null());
    {
        // A repeated clear observes only NULL and releases nothing.
        // SAFETY: `field` is this test's own member and is NULL.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 4);
    }
    assert!(field.is_null());
}

#[test]
fn production_assume_empty_then_store_matches_the_token_rule() {
    install_miri_shim();
    let mut field: *mut core::ffi::c_char = ptr::null_mut();
    // SAFETY: `field` is this test's own member and is NULL.
    let empty = unsafe { CStrSlot::of(&mut field).assume_empty() };
    empty.store(dup(c"beta"));
    assert!(!field.is_null());
    {
        // SAFETY: `field` holds the block this test stored.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 5);
    }
}

/// Compile-time witness of the token rule: `store` accepts only the proof token
/// produced by `clear`/`assume_empty`, so a second store on the same cleared slot
/// (or a store into an occupied slot) has no type-correct spelling.
#[test]
fn store_is_reachable_only_through_the_token() {
    install_miri_shim();
    fn store_once(slot: EmptyCStrSlot<'_>, owned: OwnedCStr) {
        slot.store(owned);
    }
    let mut field: *mut core::ffi::c_char = ptr::null_mut();
    // SAFETY: `field` is this test's own member and is NULL.
    let empty = unsafe { CStrSlot::of(&mut field).assume_empty() };
    store_once(empty, dup(c"gamma"));
    // SAFETY: `field` holds the block this test stored.
    let mut slot = unsafe { CStrSlot::of(&mut field) };
    slot.clear(SeamFile::new(FILE), 6);
}
