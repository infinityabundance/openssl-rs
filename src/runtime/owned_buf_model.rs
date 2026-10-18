//! Exhaustive, test-only state machine for the `OwnedBuf` release invariant (OB-1).
//!
//! The model mirrors `runtime::owned_buf`'s private release state and the exact
//! release `Drop` selects for it. It is **not** the implementation: it is an
//! independently written transition system used to check the six invariants the
//! production type claims and to show that deliberately broken rules are
//! detected (negative controls).
//!
//! The reachable-state exploration is bounded by `OWNER-CHECKS.md`'s stated
//! abstract domain (five boundary extents, two file tokens, two lines, two
//! release lines, and the boundary adoption lengths `{0, 1, extent-1, extent,
//! extent+1}`). It does not exercise the allocator, pointer provenance, concurrency,
//! or memory safety. The production correspondence tests below inspect the
//! stored `Release` arm and observe the arm `Drop` selected.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::Cell;
use core::ffi::{c_int, c_uchar, CStr};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{drop_probe, OwnedBuf, Release};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::mem_coords::SeamFile;

const FILE: &CStr = c"test/owned_buf_model.rs";
const FILE_RELEASE: &CStr = c"test/owned_buf_model_release.rs";

/// A bounded run; reaching it is reported by the exploration tests.
const MAX_TRANSITIONS: usize = 100_000;

type FileId = usize;

/// The four release arms, with every field that participates in the release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    Plain {
        file: FileId,
        line: c_int,
    },
    Cleansed {
        num: usize,
        file: FileId,
        line: c_int,
    },
    Conditional {
        num: usize,
        clear: bool,
        file: FileId,
        line: c_int,
    },
    SecureCleansed {
        num: usize,
        file: FileId,
        line: c_int,
    },
}

impl Mode {
    /// The stored cleansing length, if the arm carries one.
    fn num(self) -> Option<usize> {
        match self {
            Mode::Plain { .. } => None,
            Mode::Cleansed { num, .. }
            | Mode::Conditional { num, .. }
            | Mode::SecureCleansed { num, .. } => Some(num),
        }
    }

    fn coords(self) -> (FileId, c_int) {
        match self {
            Mode::Plain { file, line }
            | Mode::Cleansed { file, line, .. }
            | Mode::Conditional { file, line, .. }
            | Mode::SecureCleansed { file, line, .. } => (file, line),
        }
    }

    fn line(self) -> c_int {
        self.coords().1
    }

    /// Change only the diagnostic line, preserving the arm and every length/mode field.
    fn with_line(self, line: c_int) -> Mode {
        match self {
            Mode::Plain { file, .. } => Mode::Plain { file, line },
            Mode::Cleansed { num, file, .. } => Mode::Cleansed { num, file, line },
            Mode::Conditional {
                num, clear, file, ..
            } => Mode::Conditional {
                num,
                clear,
                file,
                line,
            },
            Mode::SecureCleansed { num, file, .. } => Mode::SecureCleansed { num, file, line },
        }
    }

    /// The exact authority release a correct `Drop` selects for this arm.
    fn expected_release(self) -> ReleaseCall {
        match self {
            Mode::Plain { file, line } => ReleaseCall::Plain { file, line },
            Mode::Cleansed { num, file, line } => ReleaseCall::Cleansed { num, file, line },
            Mode::Conditional {
                num,
                clear,
                file,
                line,
            } => {
                if clear {
                    ReleaseCall::Cleansed { num, file, line }
                } else {
                    ReleaseCall::Plain { file, line }
                }
            }
            Mode::SecureCleansed { num, file, line } => {
                ReleaseCall::SecureCleansed { num, file, line }
            }
        }
    }
}

fn same_tag(a: Mode, b: Mode) -> bool {
    matches!(
        (a, b),
        (Mode::Plain { .. }, Mode::Plain { .. })
            | (Mode::Cleansed { .. }, Mode::Cleansed { .. })
            | (Mode::Conditional { .. }, Mode::Conditional { .. })
            | (Mode::SecureCleansed { .. }, Mode::SecureCleansed { .. })
    )
}

/// Equality of every field except the diagnostic line.
fn same_except_line(a: Mode, b: Mode) -> bool {
    match (a, b) {
        (Mode::Plain { file: fa, .. }, Mode::Plain { file: fb, .. }) => fa == fb,
        (
            Mode::Cleansed {
                num: na, file: fa, ..
            },
            Mode::Cleansed {
                num: nb, file: fb, ..
            },
        ) => na == nb && fa == fb,
        (
            Mode::Conditional {
                num: na,
                clear: ca,
                file: fa,
                ..
            },
            Mode::Conditional {
                num: nb,
                clear: cb,
                file: fb,
                ..
            },
        ) => na == nb && ca == cb && fa == fb,
        (
            Mode::SecureCleansed {
                num: na, file: fa, ..
            },
            Mode::SecureCleansed {
                num: nb, file: fb, ..
            },
        ) => na == nb && fa == fb,
        _ => false,
    }
}

/// The function a correct `Drop` calls, or the mutant override.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ReleaseCall {
    Plain {
        file: FileId,
        line: c_int,
    },
    Cleansed {
        num: usize,
        file: FileId,
        line: c_int,
    },
    SecureCleansed {
        num: usize,
        file: FileId,
        line: c_int,
    },
}

impl ReleaseCall {
    fn num(self) -> Option<usize> {
        match self {
            ReleaseCall::Plain { .. } => None,
            ReleaseCall::Cleansed { num, .. } | ReleaseCall::SecureCleansed { num, .. } => {
                Some(num)
            }
        }
    }
}

/// The real rules and the four negative-control mutations (mutant iii has two arms).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    Real,
    /// (i) A safe constructor sets the cleansing length above the allocation.
    SafeCtorOvershoot,
    /// (ii) A setter makes a Cleansed/Secure block release as Plain.
    NonConditionalDowngrade,
    /// (iii-a) `Drop` releases twice.
    DoubleRelease,
    /// (iii-b) `into_raw` does not suppress the release.
    IntoRawLeak,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Violation {
    /// (a) A safe constructor's stored cleansing length is not the allocation length.
    SafeCtorNumNotExtent,
    /// (b) The release function does not match the stored arm.
    ReleaseModeMismatch,
    /// (c) A stored or released cleansing length exceeds the assumed extent.
    NumExceedsExtent,
    /// (d) `Drop` released more than once.
    DoubleRelease,
    /// (d) `Drop` released more than once in total.
    MultipleReleases,
    /// (d) `into_raw` released instead of transferring ownership.
    IntoRawReleased,
    /// (e) `set_clear` changed a non-Conditional arm.
    SetClearChangedNonConditional,
    /// (e) `set_clear` changed the stored length.
    SetClearChangedNum,
    /// (f) `set_release_line` changed something other than the line.
    SetReleaseLineChangedMoreThanLine,
    /// The exploration attempted an operation on a consumed handle.
    ConsumedHandleUsed,
    /// A transition changed `extent` or the stored cleansing length, so the
    /// `num <= extent` bound could not be shown to be inductively preserved.
    TransitionChangedBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    extent: usize,
    mode: Mode,
    live: bool,
    raw_taken: bool,
    releases: u32,
    last_release: Option<ReleaseCall>,
    /// Mutant (ii): the stored arm is untouched but `Drop` is forced to Plain.
    force_plain: bool,
}

impl State {
    fn new(extent: usize, mode: Mode) -> Self {
        State {
            extent,
            mode,
            live: true,
            raw_taken: false,
            releases: 0,
            last_release: None,
            force_plain: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    SetClear(bool),
    SetReleaseLine(c_int),
    IntoRaw,
    Drop,
}

const OPS: [Op; 6] = [
    Op::SetClear(false),
    Op::SetClear(true),
    Op::SetReleaseLine(7),
    Op::SetReleaseLine(9),
    Op::IntoRaw,
    Op::Drop,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeCtor {
    Plain,
    Cleansed,
    SecureCleansed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdoptKind {
    Plain,
    Cleansed,
    Conditional,
    SecureCleansed,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    extent: usize,
    num: usize,
    clear: bool,
    file: FileId,
    line: c_int,
}

#[derive(Default)]
struct Report {
    starts: usize,
    transitions: usize,
    /// Adoption cases the model refused because `num > extent`.
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

fn check_extent(state: &State, report: &mut Report) {
    if let Some(num) = state.mode.num() {
        if num > state.extent {
            report.record(Violation::NumExceedsExtent);
        }
    }
    if let Some(num) = state.last_release.and_then(ReleaseCall::num) {
        if num > state.extent {
            report.record(Violation::NumExceedsExtent);
        }
    }
}

fn safe_state(
    proto: Proto,
    ctor: SafeCtor,
    extent: usize,
    file: FileId,
    line: c_int,
    report: &mut Report,
) -> State {
    let num = match ctor {
        SafeCtor::Plain => None,
        SafeCtor::Cleansed | SafeCtor::SecureCleansed => {
            Some(if proto == Proto::SafeCtorOvershoot {
                extent.saturating_add(1)
            } else {
                extent
            })
        }
    };

    // (a) A safe constructor's cleansing length is the allocation length.
    if let Some(n) = num {
        if n != extent {
            report.record(Violation::SafeCtorNumNotExtent);
        }
    }

    let mode = match ctor {
        SafeCtor::Plain => Mode::Plain { file, line },
        SafeCtor::Cleansed => Mode::Cleansed {
            num: num.unwrap_or(0),
            file,
            line,
        },
        SafeCtor::SecureCleansed => Mode::SecureCleansed {
            num: num.unwrap_or(0),
            file,
            line,
        },
    };
    let state = State::new(extent, mode);
    check_extent(&state, report);
    state
}

/// The caller contract for every adoption constructor: the cleansing length is
/// at most the allocation extent. `num > extent` is excluded by the `# Safety`
/// contract and therefore has no corresponding model state.
fn contract_admits(extent: usize, num: usize) -> bool {
    num <= extent
}

fn adopt_state(kind: AdoptKind, case: Case, report: &mut Report) -> Option<State> {
    // The caller's contract is `num <= extent`. A `num` above it is not a state
    // the unsafe constructor may be called with, so the model has no such start
    // state; the rejection is counted and asserted by the bounds test.
    if !contract_admits(case.extent, case.num) {
        report.rejected += 1;
        return None;
    }
    let mode = match kind {
        AdoptKind::Plain => Mode::Plain {
            file: case.file,
            line: case.line,
        },
        AdoptKind::Cleansed => Mode::Cleansed {
            num: case.num,
            file: case.file,
            line: case.line,
        },
        AdoptKind::Conditional => Mode::Conditional {
            num: case.num,
            clear: case.clear,
            file: case.file,
            line: case.line,
        },
        AdoptKind::SecureCleansed => Mode::SecureCleansed {
            num: case.num,
            file: case.file,
            line: case.line,
        },
    };
    let state = State::new(case.extent, mode);
    check_extent(&state, report);
    Some(state)
}

/// Boundary extents, including the arithmetic endpoints of `usize`.
const EXTENTS: [usize; 5] = [0, 1, 4, usize::MAX - 1, usize::MAX];

/// The representative caller-supplied lengths for an adoption: `0`, `1`,
/// `extent-1`, `extent`, `extent+1`, with unrepresentable values omitted and
/// duplicates removed. `extent+1` exercises the state the `# Safety` contract
/// excludes; `extent-1` exercises the largest admitted proper prefix.
fn boundary_nums(extent: usize) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for num in [
        Some(0),
        Some(1),
        extent.checked_sub(1),
        Some(extent),
        extent.checked_add(1),
    ]
    .into_iter()
    .flatten()
    {
        if !out.contains(&num) {
            out.push(num);
        }
    }
    out
}

fn starts(proto: Proto, report: &mut Report) -> Vec<State> {
    const FILES: [FileId; 2] = [0xA, 0xB];
    const LINES: [c_int; 2] = [7, 8];

    let mut out = Vec::new();
    for extent in EXTENTS {
        for file in FILES {
            for line in LINES {
                for ctor in [
                    SafeCtor::Plain,
                    SafeCtor::Cleansed,
                    SafeCtor::SecureCleansed,
                ] {
                    out.push(safe_state(proto, ctor, extent, file, line, report));
                }
                for kind in [
                    AdoptKind::Plain,
                    AdoptKind::Cleansed,
                    AdoptKind::Conditional,
                    AdoptKind::SecureCleansed,
                ] {
                    for num in boundary_nums(extent) {
                        let clears: &[bool] = if kind == AdoptKind::Conditional {
                            &[false, true]
                        } else {
                            &[false]
                        };
                        for &clear in clears {
                            if let Some(state) = adopt_state(
                                kind,
                                Case {
                                    extent,
                                    num,
                                    clear,
                                    file,
                                    line,
                                },
                                report,
                            ) {
                                out.push(state);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn step(state: State, op: Op, proto: Proto, report: &mut Report) -> State {
    report.transitions += 1;
    let mut next = state;

    match op {
        Op::SetClear(clear) => {
            let before = next.mode;
            let mut accepted = false;
            match before {
                Mode::Conditional {
                    num, file, line, ..
                } => {
                    next.mode = Mode::Conditional {
                        num,
                        clear,
                        file,
                        line,
                    };
                    accepted = true;
                }
                _ => {
                    if proto == Proto::NonConditionalDowngrade {
                        // The mutant accepts the call and forces the release to Plain
                        // while the stored arm still says Cleansed/SecureCleansed.
                        next.force_plain = true;
                        accepted = true;
                    }
                }
            }

            // (e) `set_clear` answers only for Conditional and changes only its mode.
            if accepted && !matches!(before, Mode::Conditional { .. }) {
                report.record(Violation::SetClearChangedNonConditional);
            }
            if !same_tag(before, next.mode) {
                report.record(Violation::SetClearChangedNonConditional);
            }
            if before.num() != next.mode.num() {
                report.record(Violation::SetClearChangedNum);
            }
        }
        Op::SetReleaseLine(line) => {
            let before = next.mode;
            next.mode = before.with_line(line);
            // (f) Only the line may change.
            if !same_except_line(before, next.mode) || next.mode.line() != line {
                report.record(Violation::SetReleaseLineChangedMoreThanLine);
            }
        }
        Op::IntoRaw => {
            if !next.live {
                report.record(Violation::ConsumedHandleUsed);
                return next;
            }
            // (d) Ownership is transferred: no release now, and no later `Drop`.
            next.live = false;
            next.raw_taken = true;
            if proto == Proto::IntoRawLeak {
                next.releases += 1;
                next.last_release = Some(next.mode.expected_release());
            }
            if next.releases != 0 {
                report.record(Violation::IntoRawReleased);
            }
        }
        Op::Drop => {
            if !next.live {
                report.record(Violation::ConsumedHandleUsed);
                return next;
            }
            let expected = next.mode.expected_release();
            let released = if next.force_plain {
                let (file, line) = next.mode.coords();
                ReleaseCall::Plain { file, line }
            } else {
                expected
            };
            // (b) The release function matches the stored arm exactly.
            if released != expected {
                report.record(Violation::ReleaseModeMismatch);
            }
            next.live = false;
            let delta = if proto == Proto::DoubleRelease { 2 } else { 1 };
            next.releases += delta;
            next.last_release = Some(released);
            // (d) `Drop` releases exactly once.
            if delta != 1 {
                report.record(Violation::DoubleRelease);
            }
            if next.releases != 1 {
                report.record(Violation::MultipleReleases);
            }
        }
    }

    // (c) Algebraic preservation of the caller contract: every operation copies
    // `extent` and the stored cleansing length unchanged (the model has no
    // operation that recomputes either), so `num <= extent` is preserved for
    // every `usize`, not merely for the sampled boundary values. A transition
    // that changed either field is reported instead of silently narrowing the
    // proof to the enumerated domain.
    if next.extent != state.extent || next.mode.num() != state.mode.num() {
        report.record(Violation::TransitionChangedBound);
    }
    check_extent(&next, report);
    next
}

fn explore(proto: Proto) -> Report {
    let mut report = Report::default();
    let mut queue = VecDeque::new();
    let mut seen = BTreeSet::new();

    let starts = starts(proto, &mut report);
    report.starts = starts.len();
    for state in starts {
        if seen.insert(state) {
            queue.push_back(state);
        }
    }

    while let Some(state) = queue.pop_front() {
        if !state.live || report.transitions >= MAX_TRANSITIONS {
            continue;
        }
        for op in OPS {
            if report.transitions >= MAX_TRANSITIONS {
                break;
            }
            let next = step(state, op, proto, &mut report);
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    report
}

#[test]
fn exhaustive_real_rules_satisfy_every_invariant() {
    let report = explore(Proto::Real);
    assert!(report.starts > 0, "the harness generated no start states");
    assert!(report.transitions > 0, "the harness explored no transition");
    assert!(
        report.violations.is_empty(),
        "the real rules violated {:?} over {} transitions from {} starts",
        report.violations,
        report.transitions,
        report.starts
    );
}

#[test]
fn exhaustive_real_rules_stay_inside_the_declared_bound() {
    let report = explore(Proto::Real);
    assert!(
        report.transitions < MAX_TRANSITIONS,
        "the exploration hit the {MAX_TRANSITIONS}-transition bound"
    );
    assert!(
        report.transitions >= 1_000,
        "the declared abstract domain explored only {} transitions",
        report.transitions
    );
    println!(
        "OB-1 model (Real): {} start states, {} transitions",
        report.starts, report.transitions
    );
}

#[test]
fn adoption_outside_the_caller_contract_is_rejected() {
    assert_eq!(
        EXTENTS,
        [0, 1, 4, usize::MAX - 1, usize::MAX],
        "the boundary extent set is part of the published model bounds"
    );

    let mut probe = Report::default();
    let mut admitted = 0usize;
    let mut rejected = 0usize;
    for extent in EXTENTS {
        for num in boundary_nums(extent) {
            let case = Case {
                extent,
                num,
                clear: false,
                file: 0xA,
                line: 7,
            };
            let state = adopt_state(AdoptKind::Cleansed, case, &mut probe);
            if contract_admits(extent, num) {
                match state {
                    Some(state) => {
                        assert_eq!(state.mode.num(), Some(num));
                        assert!(num <= extent);
                        admitted += 1;
                    }
                    None => assert!(
                        !contract_admits(extent, num),
                        "admissible adoption ({extent}, {num}) must produce a state"
                    ),
                }
            } else {
                assert!(
                    state.is_none(),
                    "the model must reject num={num} > extent={extent}"
                );
                rejected += 1;
            }
        }
    }
    assert!(admitted > 0, "no admissible boundary case was generated");
    assert!(
        rejected > 0,
        "the boundary set must include at least one excluded num > extent case"
    );

    // No reachable Real state carries a cleansing length above its extent, and
    // the transition-relation check in `step` shows that no operation can create
    // one for an arbitrary `usize` (both fields are copied unchanged).
    let real = explore(Proto::Real);
    assert_eq!(
        real.violations.get(&Violation::NumExceedsExtent),
        None,
        "a reachable Real state exceeded its extent"
    );
    assert_eq!(
        real.violations.get(&Violation::TransitionChangedBound),
        None,
        "a Real transition changed the extent or the stored cleansing length"
    );

    println!(
        "OB-1 model bounds: extents={EXTENTS:?}, admitted boundary pairs={admitted}, rejected (num > extent)={rejected}, Real starts={}, Real transitions={}",
        real.starts, real.transitions
    );
    println!(
        "OB-1 adoption boundary lengths: {:?}",
        EXTENTS.map(boundary_nums)
    );
}

#[test]
fn mutant_safe_constructor_overshoot_is_detected() {
    let report = explore(Proto::SafeCtorOvershoot);
    assert!(
        report.count(Violation::SafeCtorNumNotExtent) > 0,
        "a safe constructor with num > len must break invariant (a): {:?}",
        report.violations
    );
    assert!(
        report.count(Violation::NumExceedsExtent) > 0,
        "num > len must also break invariant (c): {:?}",
        report.violations
    );
    println!(
        "OB-1 mutant (i): {:?} over {} transitions",
        report.violations, report.transitions
    );
}

#[test]
fn mutant_non_conditional_downgrade_is_detected() {
    let report = explore(Proto::NonConditionalDowngrade);
    assert!(
        report.count(Violation::SetClearChangedNonConditional) > 0,
        "a setter accepting a non-Conditional block must break invariant (e): {:?}",
        report.violations
    );
    assert!(
        report.count(Violation::ReleaseModeMismatch) > 0,
        "a Cleansed/Secure block releasing as Plain must break invariant (b): {:?}",
        report.violations
    );
    println!(
        "OB-1 mutant (ii): {:?} over {} transitions",
        report.violations, report.transitions
    );
}

#[test]
fn mutant_double_release_is_detected() {
    let report = explore(Proto::DoubleRelease);
    assert!(
        report.count(Violation::DoubleRelease) > 0 && report.count(Violation::MultipleReleases) > 0,
        "a second release must break invariant (d): {:?}",
        report.violations
    );
    println!(
        "OB-1 mutant (iii-a): {:?} over {} transitions",
        report.violations, report.transitions
    );
}

#[test]
fn mutant_into_raw_leak_is_detected() {
    let report = explore(Proto::IntoRawLeak);
    assert!(
        report.count(Violation::IntoRawReleased) > 0,
        "a non-suppressing into_raw must break invariant (d): {:?}",
        report.violations
    );
    println!(
        "OB-1 mutant (iii-b): {:?} over {} transitions",
        report.violations, report.transitions
    );
}

fn mode_of(release: &Release) -> Mode {
    match release {
        Release::Plain { file, line } => Mode::Plain {
            file: file.as_ptr() as usize,
            line: *line,
        },
        Release::Cleansed { num, file, line } => Mode::Cleansed {
            num: *num,
            file: file.as_ptr() as usize,
            line: *line,
        },
        Release::Conditional {
            num,
            clear,
            file,
            line,
        } => Mode::Conditional {
            num: *num,
            clear: *clear,
            file: file.as_ptr() as usize,
            line: *line,
        },
        Release::SecureCleansed { num, file, line } => Mode::SecureCleansed {
            num: *num,
            file: file.as_ptr() as usize,
            line: *line,
        },
    }
}

fn take_probe() -> Option<drop_probe::Call> {
    drop_probe::LAST.with(Cell::take)
}

fn clear_probe() {
    drop_probe::LAST.with(|last| last.set(None));
}

/// Assert that a seam allocation succeeded, following the module's no-`expect` lint policy.
macro_rules! allocated {
    ($value:expr) => {{
        let value = $value;
        assert!(value.is_some(), "the seam allocation must succeed");
        let Some(value) = value else { return };
        value
    }};
}

#[test]
fn safe_constructors_store_the_model_mode() {
    let file = SeamFile::new(FILE);
    let release_file = SeamFile::new(FILE_RELEASE);
    let token = file.as_ptr() as usize;
    let release_token = release_file.as_ptr() as usize;

    let plain = allocated!(OwnedBuf::new(4, file, 11));
    assert_eq!(
        mode_of(&plain.release),
        Mode::Plain {
            file: token,
            line: 11
        }
    );
    drop(plain);

    let zeroed = allocated!(OwnedBuf::new_zeroed(4, file, 12));
    assert_eq!(
        mode_of(&zeroed.release),
        Mode::Plain {
            file: token,
            line: 12
        }
    );
    drop(zeroed);

    let plain_released = allocated!(OwnedBuf::new_plain_released(4, file, 13, release_file, 14));
    assert_eq!(
        mode_of(&plain_released.release),
        Mode::Plain {
            file: release_token,
            line: 14
        }
    );
    drop(plain_released);

    let cleansed = allocated!(OwnedBuf::new_cleansed(4, file, 15));
    assert_eq!(
        mode_of(&cleansed.release),
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 15
        }
    );
    drop(cleansed);

    let cleansed_at = allocated!(OwnedBuf::new_cleansed_at(4, file, 16, 17));
    assert_eq!(
        mode_of(&cleansed_at.release),
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 17
        }
    );
    drop(cleansed_at);

    let cleansed_released = allocated!(OwnedBuf::new_cleansed_released(
        4,
        file,
        18,
        release_file,
        19
    ));
    assert_eq!(
        mode_of(&cleansed_released.release),
        Mode::Cleansed {
            num: 4,
            file: release_token,
            line: 19
        }
    );
    drop(cleansed_released);

    let zeroed_cleansed = allocated!(OwnedBuf::new_zeroed_cleansed(4, file, 20));
    assert_eq!(
        mode_of(&zeroed_cleansed.release),
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 20
        }
    );
    drop(zeroed_cleansed);

    let zeroed_cleansed_at = allocated!(OwnedBuf::new_zeroed_cleansed_at(4, file, 21, 22));
    assert_eq!(
        mode_of(&zeroed_cleansed_at.release),
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 22
        }
    );
    drop(zeroed_cleansed_at);

    // SAFETY: `num = 3` is at most the 4-byte allocation this test owns.
    let num_less = allocated!(unsafe { OwnedBuf::new_cleansed_num(4, 3, file, 23, 24) });
    assert_eq!(
        mode_of(&num_less.release),
        Mode::Cleansed {
            num: 3,
            file: token,
            line: 24
        }
    );
    drop(num_less);
}

#[test]
fn secure_safe_constructors_store_the_model_mode() {
    let _guard = crate::test_support::lock_global_state();
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;

    let secure = allocated!(OwnedBuf::new_secure_cleansed(4, file, 25));
    assert_eq!(
        mode_of(&secure.release),
        Mode::SecureCleansed {
            num: 4,
            file: token,
            line: 25
        }
    );
    drop(secure);

    let secure_zeroed = allocated!(OwnedBuf::new_secure_zalloc_cleansed(4, file, 26));
    assert_eq!(
        mode_of(&secure_zeroed.release),
        Mode::SecureCleansed {
            num: 4,
            file: token,
            line: 26
        }
    );
    drop(secure_zeroed);
}

#[test]
fn adoption_constructors_store_the_model_mode() {
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;

    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 30).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned, and
    // this test is its only owner from here on.
    let plain = allocated!(unsafe { OwnedBuf::adopt_plain(raw, file, 31) });
    assert_eq!(
        mode_of(&plain.release),
        Mode::Plain {
            file: token,
            line: 31
        }
    );
    drop(plain);

    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 32).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned; the
    // cleansing length is inside that allocation.
    let cleansed = allocated!(unsafe { OwnedBuf::adopt_cleansed(raw, 4, file, 33) });
    assert_eq!(
        mode_of(&cleansed.release),
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 33
        }
    );
    drop(cleansed);

    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 34).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned; the
    // cleansing length and the authority's `clear` decision are this test's.
    let conditional = allocated!(unsafe { OwnedBuf::adopt_conditional(raw, 4, true, file, 35) });
    assert_eq!(
        mode_of(&conditional.release),
        Mode::Conditional {
            num: 4,
            clear: true,
            file: token,
            line: 35
        }
    );
    drop(conditional);
}

#[test]
fn nullable_adoption_constructors_store_the_model_mode() {
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;

    // SAFETY: NULL is the authority's empty block.
    let plain = unsafe { OwnedBuf::adopt_plain_nullable(core::ptr::null_mut(), file, 36) };
    assert_eq!(
        mode_of(&plain.release),
        Mode::Plain {
            file: token,
            line: 36
        }
    );
    drop(plain);

    // SAFETY: NULL is the authority's empty block.
    let cleansed = unsafe { OwnedBuf::adopt_cleansed_nullable(core::ptr::null_mut(), 0, file, 37) };
    assert_eq!(
        mode_of(&cleansed.release),
        Mode::Cleansed {
            num: 0,
            file: token,
            line: 37
        }
    );
    drop(cleansed);
}

#[test]
fn secure_adoption_constructor_stores_the_model_mode() {
    let _guard = crate::test_support::lock_global_state();
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;

    let source = allocated!(OwnedBuf::new_secure_cleansed(4, file, 38));
    let raw = source.into_raw();
    // SAFETY: `raw` is the whole block a secure constructor allocated, with the
    // secure allocator's own plain fallback covered by the contract.
    let adopted = allocated!(unsafe { OwnedBuf::adopt_secure_cleansed(raw, 4, file, 39) });
    assert_eq!(
        mode_of(&adopted.release),
        Mode::SecureCleansed {
            num: 4,
            file: token,
            line: 39
        }
    );
    drop(adopted);
}

#[test]
fn set_clear_matches_the_model() {
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;
    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 40).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned.
    let adopted = unsafe { OwnedBuf::adopt_conditional(raw, 4, false, file, 41) };
    let Some(mut conditional) = adopted else {
        return;
    };
    assert_eq!(
        mode_of(&conditional.release),
        Mode::Conditional {
            num: 4,
            clear: false,
            file: token,
            line: 41
        }
    );

    assert!(conditional.set_clear(true), "Conditional accepts the flag");
    assert_eq!(
        mode_of(&conditional.release),
        Mode::Conditional {
            num: 4,
            clear: true,
            file: token,
            line: 41
        }
    );
    assert!(conditional.set_clear(false), "Conditional accepts the flag");
    assert_eq!(
        mode_of(&conditional.release),
        Mode::Conditional {
            num: 4,
            clear: false,
            file: token,
            line: 41
        }
    );
    drop(conditional);
}

#[test]
fn set_clear_never_changes_a_non_conditional_mode() {
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;

    let mut plain = allocated!(OwnedBuf::new(4, file, 42));
    let before = mode_of(&plain.release);
    assert!(!plain.set_clear(true), "Plain has no clear flag");
    assert_eq!(mode_of(&plain.release), before);
    assert_eq!(
        before,
        Mode::Plain {
            file: token,
            line: 42
        }
    );
    drop(plain);

    let mut cleansed = allocated!(OwnedBuf::new_cleansed(4, file, 43));
    let before = mode_of(&cleansed.release);
    assert!(!cleansed.set_clear(true), "Cleansed has no clear flag");
    assert_eq!(mode_of(&cleansed.release), before);
    assert_eq!(
        before,
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 43
        }
    );
    drop(cleansed);
}

#[test]
fn set_release_line_changes_only_the_line() {
    let file = SeamFile::new(FILE);
    let token = file.as_ptr() as usize;

    let mut plain = allocated!(OwnedBuf::new(4, file, 44));
    plain.set_release_line(90);
    assert_eq!(
        mode_of(&plain.release),
        Mode::Plain {
            file: token,
            line: 90
        }
    );
    drop(plain);

    let mut cleansed = allocated!(OwnedBuf::new_cleansed(4, file, 45));
    cleansed.set_release_line(91);
    assert_eq!(
        mode_of(&cleansed.release),
        Mode::Cleansed {
            num: 4,
            file: token,
            line: 91
        }
    );
    drop(cleansed);

    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 46).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned.
    let adopted = unsafe { OwnedBuf::adopt_conditional(raw, 4, true, file, 47) };
    let Some(mut conditional) = adopted else {
        return;
    };
    conditional.set_release_line(92);
    assert_eq!(
        mode_of(&conditional.release),
        Mode::Conditional {
            num: 4,
            clear: true,
            file: token,
            line: 92
        }
    );
    drop(conditional);
}

#[test]
fn drop_dispatch_matches_the_model_for_every_mode() {
    let file = SeamFile::new(FILE);

    let plain = allocated!(OwnedBuf::new(4, file, 48));
    clear_probe();
    drop(plain);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call::Plain),
        "Plain must select CRYPTO_free"
    );

    let cleansed = allocated!(OwnedBuf::new_cleansed(4, file, 49));
    clear_probe();
    drop(cleansed);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call::Cleansed { num: 4 }),
        "Cleansed must select CRYPTO_clear_free over the stored length"
    );

    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 50).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned.
    let conditional = allocated!(unsafe { OwnedBuf::adopt_conditional(raw, 4, true, file, 51) });
    clear_probe();
    drop(conditional);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call::Cleansed { num: 4 }),
        "Conditional(clear) must select CRYPTO_clear_free"
    );

    let raw = CRYPTO_malloc(4, FILE.as_ptr(), 52).cast::<c_uchar>();
    assert!(!raw.is_null(), "the seam must allocate 4 bytes");
    // SAFETY: `raw` is the whole block a fresh plain seam allocation returned.
    let conditional = allocated!(unsafe { OwnedBuf::adopt_conditional(raw, 4, false, file, 53) });
    clear_probe();
    drop(conditional);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call::Plain),
        "Conditional(!clear) must select CRYPTO_free"
    );

    let _guard = crate::test_support::lock_global_state();
    let secure = allocated!(OwnedBuf::new_secure_cleansed(4, file, 54));
    clear_probe();
    drop(secure);
    assert_eq!(
        take_probe(),
        Some(drop_probe::Call::SecureCleansed { num: 4 }),
        "SecureCleansed must select CRYPTO_secure_clear_free"
    );
}

#[test]
fn into_raw_suppresses_the_release_in_production() {
    let file = SeamFile::new(FILE);
    let buf = allocated!(OwnedBuf::new(4, file, 55));
    clear_probe();
    let raw = buf.into_raw();
    assert!(!raw.is_null());
    assert_eq!(take_probe(), None, "into_raw must not run Drop");
    // SAFETY: `raw` is the whole block allocated above and is released here exactly
    // once; no `OwnedBuf` still owns it.
    unsafe { CRYPTO_free(raw.cast(), FILE.as_ptr(), 55) };
}
