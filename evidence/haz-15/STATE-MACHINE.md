# HAZ-15 follow-up — bounded exploration of the first-use secret state machine

Status: the external-key first-use secret store is explored by a **deterministic
interleaving model** in-crate, not by Loom. The model enumerates every reachable
interleaving of three actors over two objects, checks five invariants at every state, and
proves each invariant is connected to a checker by a deliberately faulty transition.
A finite conformance suite replays named scenarios against the real store. The refinement
gap — what the model omits and why it is not a proof about the implementation — is stated
in §8.

`HAZ-15` stays `CLAIMED_NO_EVIDENCE`; nothing here closes the returned-length channel.

## 1. Identity

| field | value |
|---|---|
| branch / HEAD | `staging` at `618f5e6ec6913fc41abb0c791c924bc55b6ed4df`, clean at the start |
| model source | `src/rsa/ext_kdk_model.rs`, declared `#[cfg(test)]` in `src/rsa/mod.rs` |
| model tests | `rsa::ossl::tests::the_state_machine_exploration_finds_no_invariant_violation`, `every_invariant_has_a_fault_the_exploration_catches`, `the_model_agrees_with_the_store_on_the_named_scenarios` |
| court | `openssl-rs-court-tools:1`, 6g/6g cap, `CARGO_BUILD_JOBS=4` |
| `Cargo.toml` / `Cargo.lock` | **unchanged** by this batch |

## 2. Why Loom was not used, and what it would cost

`loom` is already admitted for this crate: `Cargo.toml` carries
`[target.'cfg(loom)'.dev-dependencies] loom = "0.7"` and `Cargo.lock` resolves
`loom 0.7.2` for the `cfg(loom)` build. Admitting it for the store is therefore **not** a
lock-file decision. It was still not used, for reasons that are about this store's shape:

1. **The store is a process-wide `static Mutex<ExtKdkStore>` plus a `static Condvar`.**
   Loom objects must be created inside `loom::model`, because they are bound to that
   model's execution context; a `static` is created once, before any model runs. Driving
   the store under Loom therefore needs the store to be **passed in**, which means
   threading a store handle through `per_key_ext_kdk_secret`,
   `publish_ext_kdk_secret`, `abandon_ext_kdk_reservation`, `forget_ext_kdk_secret` and
   the test observers — and `forget_ext_kdk_secret` is called from
   `Rsa::destroy_body`, i.e. from the public destructor path. That is a change to the
   implementation the existing re-entrancy evidence is bound to, not a harness.
2. **The owner identity is `std::thread::ThreadId`**, which Loom does not model; it would
   need a seam with a Loom-side actor identity.
3. **The wait is a wall-clock deadline.** Loom 0.7.2's `Condvar` does have
   `wait_timeout` (verified in the fetched source), but Loom models *scheduling*, not
   time: `loom-0.7.2/src/` has no time module and no `Instant`. The
   `EXT_KDK_WAIT_LIMIT` deadline and the `WaitTimedOut` transition — one of the model's
   required events — cannot be produced by a Loom run without adding a modelled clock the
   store does not have.
4. **The draw is `RAND_priv_bytes`**, a real global RNG reached from the modelled region.
   A Loom run would need a stub under `cfg(loom)`, i.e. the modelled transition sequence
   would not be the one the crate executes.

A Loom harness that modelled only the non-timeout transitions would be a *second*
abstraction — the same kind of artefact as the model below, with the same refinement gap
and none of the exhaustiveness, at the cost of rewriting the production path. The model
was chosen instead, and the Loom seam is recorded as a follow-up whose first cost is
item 1.

## 3. The model

### 3.1 States

The store is a list of entries, as the implementation's boxed vector is:

```
Entry  { object, reservation, slot }
Slot   = Initializing { owner } | Ready { secret, published_under }
```

There is deliberately **no persistent `Abandoned` state**. The implementation removes the
reservation in one locked step (`retain`), so `abandon` is a transition
`Initializing → Absent` plus the parked waiter's `ReservationAbandoned` outcome. A
persistent `Abandoned` state would enumerate interleavings the implementation cannot
exhibit, i.e. it would be a widening, not a refinement. The four-state vocabulary from
the task is therefore represented as three store states plus the `abandon` event.

Each actor additionally carries a mode (`Start`, `Drawing`, `Publishing`, `Waiting`,
`Destroying`, `Done`), an `owned` reservation record and a `waiting` observation.

### 3.2 Events and transitions

| event | preconditions | effect | outcomes |
|---|---|---|---|
| `Reserve(object)` | actor not parked | **one atomic critical section**: look up the object, then serve, refuse, park or reserve | `Secret` (hit), `Reentrant` (own reservation), `Parked` (peer's), `Reserved` (absent) |
| `DrawSuccess(object)` | actor owns a reservation for the object | none (the secret is created at publication) | `Drawn` |
| `DrawFailure(object)` | actor owns a reservation | remove by exact reservation (a no-op if already removed) | `Abandoned` |
| `Abandon(object)` | actor owns a reservation | remove by exact reservation | `Abandoned` |
| `Publish(object)` | actor owns a reservation | install `Ready{secret, published_under = reservation}` **only** if the current entry is that exact reservation owned by that actor; otherwise refuse | `Published`, `PublishRefused` |
| `Destroy(object)` | — | remove every entry for the object | `Destroyed` |
| `Woken(object)` | actor parked on the object | re-check: same reservation present → loop again; otherwise abandon | `Resumed`, `ReservationAbandoned` |
| `Timeout(object)` | actor parked on the object | — | `WaitTimedOut` |

`Reserve` is one event because the implementation holds the store's lock across the
lookup and the reservation, so no other actor can interleave between them. Splitting it
into separately schedulable `lookup` and `reserve` events would enumerate an interleaving
the implementation excludes. The peer wait is the `Parked` outcome of `Reserve` plus the
`Woken` event; a spurious wake is `Woken → Resumed → Reserve`, which parks again on the
same reservation.

### 3.3 Exploration

Depth-first over the reachable state graph. The visited set is keyed on a **normalised**
state: reservation ids are ranked by their order among the ids live in the state, because
absolute ids change with the path and would otherwise defeat memoisation; the
per-object publication counter is omitted because no invariant depends on it. Each actor's
enabled events are derived from its mode, and its next mode is derived from the outcome,
so the exploration follows the *reachable* transitions rather than a fixed script.

| scenario | actors | states visited | truncated |
|---|---|---|---|
| a concurrent first use and a destruction | `Start(0)`, `Start(0)`, `Destroy(0)` | **248** | no |
| two objects and a re-entrant caller | `Start(0)`, `Start(1)`, `Start(0)` | **670** | no |
| three callers on one object | `Start(0)`, `Start(0)`, `Start(0)` | **397** | no |

Bound: `NODE_BUDGET = 200_000` visited states per exploration. The controls additionally
assert the observed working size stays **below 20 000**, so a growth in the model's state
space fails the test rather than passing quietly inside the budget. A `truncated` run is
refused by the test: the claim is completeness **inside** the bound, and the bound was not
reached.

Reachable outcomes asserted per scenario: `Reserved`, `Drawn`, `Published`, `Reentrant`,
`Parked`, `Abandoned`, `WaitTimedOut`, and at least one `Secret`; scenarios with a
destroyer also reach `Destroyed`, `PublishRefused` and `ReservationAbandoned`, and
scenarios without one must **not** reach `Destroyed`.

## 4. Invariants and their checkers

| id | invariant | checked |
|---|---|---|
| I1 | at most one entry per object, and at most one `Ready` entry per object (one secret per live object) | `Machine::check_state`, after every event |
| I2 | a secret is installed only into its own current reservation | `published_under == reservation` for every `Ready` entry |
| I3 | no waiter observes a secret for a different object | the secret's tag is the object, checked when served and on every `Ready` entry |
| I4 | destruction leaves no entry for the destroyed object | transition postcondition in `Destroy` |
| I5 | a refused re-entry leaves the store unchanged | the entry list is snapshotted around the `Reentrant` arm and compared |

## 5. Negative controls

Each control arms one deliberately wrong transition and requires the exploration to reach
it and report the matching violation
(`every_invariant_has_a_fault_the_exploration_catches`):

| fault | violation observed |
|---|---|
| `ReserveOverExisting` (reserve installs a second entry) | `DuplicateEntry` |
| `PublishIgnoresReservation` (publish under a reservation that is not the entry's) | `PublishedIntoStaleReservation` |
| `CrossObjectSecret` (publish tags the secret with the other object) | `CrossObjectSecret` |
| `DestroyKeepsEntry` (destruction leaves the entry) | `DestroyLeftEntry` |
| `ReentryPushes` (a refused re-entry installs a reservation) | `RefusalMutatedStore` |

Every fault is detected, and every violation carries a non-empty path. Without this, a
green exploration would only show that the checker never fired, not that it is connected.

## 6. Conformance with the real store

`the_model_agrees_with_the_store_on_the_named_scenarios` fixes the model's transition
outputs for five scenarios and executes the two rows the store can run on one thread:

| scenario | model | store |
|---|---|---|
| same-thread re-entry | `Reserved, Drawn, Reentrant, Published` | outer `1`, inner `0` with `ReentrantInitialization`, one `Ready` entry — `a_reentrant_call_for_the_mid_initialisation_object_is_refused` |
| destruction during initialisation | `Reserved, Parked, Drawn, Destroyed, PublishRefused, ReservationAbandoned` | owner `0`, waiter `ReservationAbandoned`, no entry — `destruction_during_initialisation_is_a_defined_refusal` |
| draw failure, then retry | `Reserved, Abandoned, Reserved` | `RngFailure` with no entry, then `1` — **executed in this test** |
| reservation allocation failure | abandonment after `Reserve` | `AllocationFailure` with no entry — **executed in this test** |
| bounded wait expires | `Reserved, Parked, WaitTimedOut` | `WaitTimedOut` after 5.01 s, then the owner publishes the one secret — `a_peer_wait_that_is_never_satisfied_is_the_bounded_timeout` |

The rows that need no second thread are executed in this test and compared with the
model's output. The threaded rows are established by the named store controls in the
table, not re-executed here; that is the conformance check's scope.

## 7. What the exploration establishes, and what it does not

Establishes: for each of the three scenarios, **every** interleaving reachable in the
model (248 / 670 / 397 states) satisfies I1–I5, and every invariant has a fault the
checker catches. It also records the reachable outcome set for the state machine.

Does not establish: that the model is the implementation. The model's transition function
is a transcription of `per_key_ext_kdk_secret`, `publish_ext_kdk_secret`,
`abandon_ext_kdk_reservation` and `forget_ext_kdk_secret`, checked line by line and
conformed on the rows in §6, but no refinement proof exists and the conformance suite is
finite.

## 8. The refinement gap

Omitted from the model, and therefore not covered by the exploration:

* **Memory ordering.** The store's transitions are all under one mutex, so the model's
  atomic steps are faithful for the entry state, but the model does not reason about the
  acquire/release edges of the mutex or the condition variable. A Loom run would; it is
  the instrument for this axis and is not run (§2).
* **Spurious wakeups.** Modelled as `Woken → Resumed → Reserve`, which is the
  implementation's loop, but the number of spurious wakeups and their timing are not.
* **Real time.** `EXT_KDK_WAIT_LIMIT` is a wall-clock bound. `Timeout` is a schedulable
  event that the explorer may take at any point; it cannot show that the deadline is
  reached after 5 s of real time, nor that a peer's publish at 4.999 s is observed.
* **Allocation failure timing.** Reservation, vector-growth and secret allocation are
  modelled as a single `DrawFailure`/`Abandon`, not as separately interleavable failures.
  The store's real failure points are exercised by panic and fault injection in
  `CALLBACK-CONTRACT.md` §5, not here.
* **Address reuse and thread-id reuse.** The model's objects are slots and its owners are
  actor indices. The implementation keys entries on the object's address and realises the
  owner as a `ThreadId`; the reservation id, not the address, is what publication checks,
  and that is modelled, but reuse of an address or a thread id is not.
* **Poisoning.** The implementation's lock helper recovers from a poisoned mutex; the
  model has no poison state, so "a panic left the lock poisoned but usable" is outside it.
  That is covered by the panic-injection control.
* **The RNG and the KDF.** `RAND_priv_bytes` and `hmac_sha256_kdf` are outside the model;
  the exploration says nothing about them.
* **More than three actors, more than two objects.** Bounded by construction. Three
  callers on one object is the widest scenario explored.

## 9. Reproducibility

No dependency was added and neither `Cargo.toml` nor `Cargo.lock` changed, so a build
from this tree resolves exactly as before. The model is standard-library-only and
`#[cfg(test)]`, so it appears in no release binary and costs nothing at load time. The
state counts in §3.3 are deterministic: the explorer's worklist order is a fixed event
order and the visited set is used only for membership.
