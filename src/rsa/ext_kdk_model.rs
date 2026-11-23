//! A deterministic interleaving model of the external-key first-use secret store.
//!
//! `per_key_ext_kdk_secret` is a small concurrent state machine: one entry per
//! object, an `Initializing` reservation owned by one thread, a `Ready` secret,
//! a bounded peer wait, and a destruction hook that removes the entry. The
//! controls in `rsa::ossl` drive named scenarios; this module enumerates the
//! reachable interleavings of the same transitions over an abstract store and
//! checks the invariants at every reachable state, with a deliberately faulty
//! transition for each invariant as a negative control.
//!
//! **What this is not.** It is a hand-written abstraction of the implementation,
//! not the implementation. Its values are that (a) the reachable outcomes and
//! invariant failures are enumerated exhaustively within a stated bound, and
//! (b) a model that can be *made* to fail proves the checker is connected.
//! The refinement gap — the finite list of transition correspondences and the
//! scenarios replayed against the real store — is recorded in
//! `evidence/haz-15/STATE-MACHINE.md`. Nothing here is linked into a release
//! build: the module is `#[cfg(test)]` and the crate has no `loom` seam for this
//! store (see that document for why).
//!
//! The state vocabulary follows the implementation rather than a textbook: there
//! is no persistent `Abandoned` state, because the implementation removes the
//! reservation in one locked step (`retain`), so `abandon` is a transition
//! `Initializing → Absent` plus the parked waiter's `ReservationAbandoned`
//! outcome. Modelling a persistent `Abandoned` state would add interleavings the
//! implementation cannot exhibit.

use std::collections::{BTreeSet, HashSet};

/// Object slots the model can address.
pub(crate) const OBJECTS: usize = 2;
/// Actors (threads or same-thread callbacks) the exploration schedules.
pub(crate) const ACTORS: usize = 3;
/// Hard bound on the states one exploration may visit.
pub(crate) const NODE_BUDGET: usize = 200_000;

/// The reserve decision the implementation makes under the store's lock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Slot {
    /// A reservation, with the owner that will publish or abandon it.
    Initializing { owner: u8 },
    /// The one published secret, and the reservation it was published under.
    Ready { secret: u64, published_under: u32 },
}

/// One store entry, as the implementation's boxed vector holds it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Entry {
    pub object: u8,
    pub reservation: u32,
    pub slot: Slot,
}

/// The schedulable events. `Reserve` is the implementation's whole locked
/// critical section (look up, then either serve, refuse, park or reserve); the
/// implementation holds the store's lock across both halves, so they are one
/// atomic step here too.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Event {
    Reserve(u8),
    DrawSuccess(u8),
    DrawFailure(u8),
    Abandon(u8),
    Publish(u8),
    Destroy(u8),
    Woken(u8),
    Timeout(u8),
}

/// What an event answered.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Outcome {
    Reserved,
    Secret(u64),
    Reentrant,
    Parked,
    Drawn,
    Abandoned,
    Published,
    PublishRefused,
    Resumed,
    ReservationAbandoned,
    WaitTimedOut,
    Destroyed,
}

/// An invariant or precondition the model broke.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Violation {
    /// An actor ran an event while it was parked.
    EventWhileWaiting,
    /// Two entries for one object.
    DuplicateEntry,
    /// Two published secrets for one object.
    TwoSecrets,
    /// A secret installed into a reservation that is not the current one.
    PublishedIntoStaleReservation,
    /// A secret tagged for a different object reached a caller.
    CrossObjectSecret,
    /// Destruction left an entry for the destroyed object.
    DestroyLeftEntry,
    /// A refused re-entry changed the store.
    RefusalMutatedStore,
    /// A draw without an owned reservation.
    DrawnWithoutReservation,
    /// A publish without an owned reservation, or for the wrong object.
    PublishedWithoutReservation,
    /// A wake for an object the actor was not waiting on.
    WaitWrongObject,
    /// A wake or timeout without a parked wait.
    NotWaiting,
}

/// A deliberately faulty transition, used as the negative control for the
/// invariant it violates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fault {
    /// The correct transition function.
    None,
    /// Reserve installs a second entry for an object that already has one.
    ReserveOverExisting,
    /// Publish installs `Ready` under a reservation id that is not the entry's.
    PublishIgnoresReservation,
    /// Publish tags the secret with the other object's identity.
    CrossObjectSecret,
    /// Destroy leaves the entry in place.
    DestroyKeepsEntry,
    /// A refused re-entry installs a fresh reservation.
    ReentryPushes,
}

/// The abstract store plus the actors' ownership and wait records.
#[derive(Clone, Debug)]
pub(crate) struct Machine {
    entries: Vec<Entry>,
    next_reservation: u32,
    publications: [u32; OBJECTS],
    owned: [Option<(u8, u32)>; ACTORS],
    waiting: [Option<(u8, u32)>; ACTORS],
    fault: Fault,
}

impl Machine {
    pub(crate) fn new(fault: Fault) -> Self {
        Self {
            entries: Vec::new(),
            next_reservation: 1,
            publications: [0; OBJECTS],
            owned: [None; ACTORS],
            waiting: [None; ACTORS],
            fault,
        }
    }

    fn reserve_id(&mut self) -> u32 {
        let reservation = self.next_reservation;
        self.next_reservation = self.next_reservation.wrapping_add(1);
        reservation
    }

    fn remove_reservation(&mut self, object: u8, reservation: u32) {
        self.entries
            .retain(|entry| !(entry.object == object && entry.reservation == reservation));
    }

    fn require_owned(&self, actor: u8, object: u8) -> Result<(), Violation> {
        match self.owned[actor as usize] {
            Some((owner_object, _)) if owner_object == object => Ok(()),
            _ => Err(Violation::DrawnWithoutReservation),
        }
    }

    /// Apply one event. The preconditions are the implementation's; a
    /// violation of one is a model defect (or the armed fault).
    pub(crate) fn apply(&mut self, actor: u8, event: Event) -> Result<Outcome, Violation> {
        let a = actor as usize;
        if a >= ACTORS {
            return Err(Violation::EventWhileWaiting);
        }
        match event {
            Event::Reserve(object) => {
                if self.waiting[a].is_some() {
                    return Err(Violation::EventWhileWaiting);
                }
                if self.fault == Fault::ReserveOverExisting {
                    let reservation = self.reserve_id();
                    self.entries.push(Entry {
                        object,
                        reservation,
                        slot: Slot::Initializing { owner: actor },
                    });
                    self.owned[a] = Some((object, reservation));
                    return Ok(Outcome::Reserved);
                }
                let found = self.entries.iter().position(|entry| entry.object == object);
                if let Some(index) = found {
                    let slot = self.entries[index].slot.clone();
                    let reservation = self.entries[index].reservation;
                    return match slot {
                        Slot::Ready { secret, .. } => {
                            if secret & 0xff != u64::from(object) {
                                return Err(Violation::CrossObjectSecret);
                            }
                            Ok(Outcome::Secret(secret))
                        }
                        Slot::Initializing { owner } => {
                            if owner == actor {
                                let before = self.entries.clone();
                                if self.fault == Fault::ReentryPushes {
                                    let extra = self.reserve_id();
                                    self.entries.push(Entry {
                                        object,
                                        reservation: extra,
                                        slot: Slot::Initializing { owner: actor },
                                    });
                                }
                                if self.entries != before {
                                    return Err(Violation::RefusalMutatedStore);
                                }
                                Ok(Outcome::Reentrant)
                            } else {
                                self.waiting[a] = Some((object, reservation));
                                Ok(Outcome::Parked)
                            }
                        }
                    };
                }
                let reservation = self.reserve_id();
                self.entries.push(Entry {
                    object,
                    reservation,
                    slot: Slot::Initializing { owner: actor },
                });
                self.owned[a] = Some((object, reservation));
                Ok(Outcome::Reserved)
            }
            Event::DrawSuccess(object) => {
                self.require_owned(actor, object)?;
                Ok(Outcome::Drawn)
            }
            Event::DrawFailure(object) | Event::Abandon(object) => {
                self.require_owned(actor, object)?;
                let reservation = self.owned[a].take().map(|(_, res)| res).unwrap_or(0);
                // The guard removes the reservation by its exact id; if the object was
                // destroyed during the draw there is nothing to remove, which is the
                // implementation's `retain` no-op.
                self.remove_reservation(object, reservation);
                Ok(Outcome::Abandoned)
            }
            Event::Publish(object) => {
                let Some((owner_object, reservation)) = self.owned[a].take() else {
                    return Err(Violation::PublishedWithoutReservation);
                };
                if owner_object != object {
                    return Err(Violation::PublishedWithoutReservation);
                }
                let found = self.entries.iter().position(|entry| {
                    entry.object == object
                        && entry.reservation == reservation
                        && matches!(entry.slot, Slot::Initializing { owner } if owner == actor)
                });
                let count = self.publications[object as usize];
                self.publications[object as usize] += 1;
                let tag = if self.fault == Fault::CrossObjectSecret {
                    u64::from(object) ^ 1
                } else {
                    u64::from(object)
                };
                let secret = (u64::from(count) << 8) | tag;
                let published_under = if self.fault == Fault::PublishIgnoresReservation {
                    reservation.wrapping_add(7)
                } else {
                    reservation
                };
                match found {
                    Some(index) => {
                        self.entries[index].slot = Slot::Ready {
                            secret,
                            published_under,
                        };
                        Ok(Outcome::Published)
                    }
                    None => {
                        // The reservation is gone: destruction removed it, or a failed
                        // initialiser abandoned it. The fault installs `Ready` anyway.
                        if self.fault == Fault::PublishIgnoresReservation {
                            self.entries.push(Entry {
                                object,
                                reservation,
                                slot: Slot::Ready {
                                    secret,
                                    published_under,
                                },
                            });
                        }
                        Ok(Outcome::PublishRefused)
                    }
                }
            }
            Event::Destroy(object) => {
                if self.fault != Fault::DestroyKeepsEntry {
                    self.entries.retain(|entry| entry.object != object);
                }
                if self.fault == Fault::DestroyKeepsEntry
                    && self.entries.iter().any(|entry| entry.object == object)
                {
                    return Err(Violation::DestroyLeftEntry);
                }
                Ok(Outcome::Destroyed)
            }
            Event::Woken(object) => {
                let Some((waiting_object, reservation)) = self.waiting[a].take() else {
                    return Err(Violation::NotWaiting);
                };
                if waiting_object != object {
                    return Err(Violation::WaitWrongObject);
                }
                if self
                    .entries
                    .iter()
                    .any(|entry| entry.object == object && entry.reservation == reservation)
                {
                    // The loop re-runs: the entry is the one observed, so the next
                    // locked step serves, refuses or parks again.
                    Ok(Outcome::Resumed)
                } else {
                    Ok(Outcome::ReservationAbandoned)
                }
            }
            Event::Timeout(object) => {
                let Some((waiting_object, _)) = self.waiting[a].take() else {
                    return Err(Violation::NotWaiting);
                };
                if waiting_object != object {
                    return Err(Violation::WaitWrongObject);
                }
                Ok(Outcome::WaitTimedOut)
            }
        }
    }

    /// The state invariants: at most one entry and one secret per object, and
    /// every published secret belongs to its object and to its own reservation.
    pub(crate) fn check_state(&self) -> Result<(), Violation> {
        for object in 0..OBJECTS {
            let object = object as u8;
            let entries = self
                .entries
                .iter()
                .filter(|entry| entry.object == object)
                .count();
            if entries > 1 {
                return Err(Violation::DuplicateEntry);
            }
            let secrets = self
                .entries
                .iter()
                .filter(|entry| entry.object == object && matches!(entry.slot, Slot::Ready { .. }))
                .count();
            if secrets > 1 {
                return Err(Violation::TwoSecrets);
            }
        }
        for entry in &self.entries {
            if let Slot::Ready {
                secret,
                published_under,
            } = entry.slot
            {
                if published_under != entry.reservation {
                    return Err(Violation::PublishedIntoStaleReservation);
                }
                if secret & 0xff != u64::from(entry.object) {
                    return Err(Violation::CrossObjectSecret);
                }
            }
        }
        Ok(())
    }

    fn reservation_ids(&self, modes: &[Mode; ACTORS]) -> Vec<u32> {
        let mut ids: Vec<u32> = Vec::new();
        for entry in &self.entries {
            ids.push(entry.reservation);
            if let Slot::Ready {
                published_under, ..
            } = entry.slot
            {
                ids.push(published_under);
            }
        }
        for waiting in self.waiting.iter().flatten() {
            ids.push(waiting.1);
        }
        for mode in modes {
            if let Mode::Waiting(_, reservation) = mode {
                ids.push(*reservation);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn rank(ids: &[u32], id: u32) -> u16 {
        u16::try_from(ids.iter().position(|&x| x == id).unwrap_or(ids.len())).unwrap_or(u16::MAX)
    }

    /// A canonical key for memoisation: reservation ids are replaced by their
    /// rank among the ids live in the state, because absolute ids do not affect
    /// any invariant and would otherwise defeat the visited set.
    fn key(&self, modes: &[Mode; ACTORS]) -> StateKey {
        let ids = self.reservation_ids(modes);
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                let (kind, extra) = match entry.slot {
                    Slot::Initializing { .. } => (0u8, entry.reservation),
                    Slot::Ready {
                        published_under, ..
                    } => (1u8, published_under),
                };
                (
                    entry.object,
                    kind,
                    Self::rank(&ids, entry.reservation),
                    Self::rank(&ids, extra),
                )
            })
            .collect();
        let waiting = self
            .waiting
            .iter()
            .map(|slot| match slot {
                Some((object, reservation)) => (*object, Self::rank(&ids, *reservation)),
                None => (u8::MAX, u16::MAX),
            })
            .collect();
        let owned = self
            .owned
            .iter()
            .map(|slot| match slot {
                Some((object, reservation)) => (*object, Self::rank(&ids, *reservation)),
                None => (u8::MAX, u16::MAX),
            })
            .collect();
        let modes = modes
            .iter()
            .map(|mode| match mode {
                Mode::Start(object) => (*object, 0u8, 0u16),
                Mode::Drawing(object) => (*object, 1, 0),
                Mode::Publishing(object) => (*object, 2, 0),
                Mode::Waiting(object, reservation) => (*object, 3, Self::rank(&ids, *reservation)),
                Mode::Destroying(object) => (*object, 4, 0),
                Mode::Done => (u8::MAX, 5, 0),
            })
            .collect();
        StateKey {
            entries,
            waiting,
            owned,
            modes,
        }
    }
}

/// The canonical, id-normalised state. The per-object publication counter is
/// deliberately absent: no invariant depends on which publication number a
/// secret carries, and including it would only split equivalent states.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct StateKey {
    entries: Vec<(u8, u8, u16, u16)>,
    waiting: Vec<(u8, u16)>,
    owned: Vec<(u8, u16)>,
    modes: Vec<(u8, u8, u16)>,
}

/// Where an actor is in its own program. The explorer picks one enabled event
/// from one actor at each step; the mode is derived from the previous outcome,
/// so a program is a nondeterministic tree rather than a fixed script.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Start(u8),
    Drawing(u8),
    Publishing(u8),
    Waiting(u8, u32),
    Destroying(u8),
    Done,
}

fn allowed(mode: Mode) -> Vec<Event> {
    match mode {
        Mode::Start(object) => vec![Event::Reserve(object)],
        Mode::Drawing(object) => vec![
            // The owner may re-enter through an application RNG callback while it is
            // drawing; the implementation answers the named refusal and does not wait
            // on its own reservation.
            Event::Reserve(object),
            Event::DrawSuccess(object),
            Event::DrawFailure(object),
            Event::Abandon(object),
        ],
        Mode::Publishing(object) => vec![Event::Publish(object)],
        Mode::Waiting(object, _) => vec![Event::Woken(object), Event::Timeout(object)],
        Mode::Destroying(object) => vec![Event::Destroy(object)],
        Mode::Done => Vec::new(),
    }
}

fn advance(mode: Mode, outcome: Outcome, machine: &Machine, actor: usize) -> Mode {
    match mode {
        Mode::Start(object) => match outcome {
            Outcome::Reserved => Mode::Drawing(object),
            Outcome::Parked => Mode::Waiting(
                object,
                machine.waiting[actor].map(|(_, res)| res).unwrap_or(0),
            ),
            _ => Mode::Done,
        },
        Mode::Drawing(object) => match outcome {
            Outcome::Drawn => Mode::Publishing(object),
            Outcome::Reentrant => Mode::Drawing(object),
            _ => Mode::Done,
        },
        Mode::Publishing(_) | Mode::Destroying(_) | Mode::Done => Mode::Done,
        Mode::Waiting(object, _) => match outcome {
            Outcome::Resumed => Mode::Start(object),
            _ => Mode::Done,
        },
    }
}

/// The result of one exploration.
#[derive(Default, Debug)]
pub(crate) struct Exploration {
    /// States popped from the worklist (including revisits).
    pub(crate) states: usize,
    /// Outcomes observed along at least one reachable path.
    pub(crate) outcomes: BTreeSet<Outcome>,
    /// Set when the node budget was exhausted, so the enumeration is not complete.
    pub(crate) truncated: bool,
    /// The first invariant or precondition violation reached, with its trace.
    pub(crate) violation: Option<(Violation, Vec<(u8, Event)>)>,
}

/// One worklist entry: a machine, each actor's mode, and the path that reached it.
type WorkItem = (Machine, [Mode; ACTORS], Vec<(u8, Event)>);

/// Enumerate every reachable interleaving of `initial` under `fault`.
pub(crate) fn explore(initial: [Mode; ACTORS], fault: Fault) -> Exploration {
    let mut report = Exploration::default();
    let mut seen: HashSet<StateKey> = HashSet::new();
    let mut stack: Vec<WorkItem> = vec![(Machine::new(fault), initial, Vec::new())];

    while let Some((machine, modes, trace)) = stack.pop() {
        report.states += 1;
        if report.states > NODE_BUDGET {
            report.truncated = true;
            break;
        }
        if !seen.insert(machine.key(&modes)) {
            continue;
        }
        if let Err(violation) = machine.check_state() {
            report.violation = Some((violation, trace));
            return report;
        }
        for (actor, mode) in modes.iter().enumerate() {
            for event in allowed(*mode) {
                let mut next = machine.clone();
                let mut next_modes = modes;
                match next.apply(actor as u8, event) {
                    Ok(outcome) => {
                        report.outcomes.insert(outcome);
                        next_modes[actor] = advance(*mode, outcome, &next, actor);
                        if let Err(violation) = next.check_state() {
                            report.violation = Some((violation, trace.clone()));
                            return report;
                        }
                        let mut next_trace = trace.clone();
                        next_trace.push((actor as u8, event));
                        stack.push((next, next_modes, next_trace));
                    }
                    Err(violation) => {
                        report.violation = Some((violation, trace.clone()));
                        return report;
                    }
                }
            }
        }
    }
    report
}

/// Apply a fixed event sequence, for the conformance comparison against the
/// real store.
pub(crate) fn run_linear(script: &[(u8, Event)]) -> Result<Vec<Outcome>, Violation> {
    let mut machine = Machine::new(Fault::None);
    let mut outcomes = Vec::new();
    for &(actor, event) in script {
        let outcome = machine.apply(actor, event)?;
        machine.check_state()?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
