# HAZ-15 follow-up — the supported caller contract for callbacks on the destruction and first-use paths

Status: the callback classes that the existing controls covered only as re-entrant
**reads** are now classified and demonstrated one by one: two are **supported** with the
invariant that makes them safe, one is **supported with a recorded ownership
consequence**, and two are **outside the contract** with the reason and the caller
obligation stated. Panic injection covers every fallible step of the first-use secret
path and every destructor position of `OPENSSL_sk_pop_free`. One new defect was found and
repaired (a guard/lock ordering that deadlocked on unwind); one is recorded and left for
HAZ-16 (a destructor that releases the stack it runs on is a second release of one
allocation).

`HAZ-15` remains `CLAIMED_NO_EVIDENCE` and `OBL-RSA-EXTKEY-ORACLE` remains open: nothing
here closes the returned-length channel, and no evidence class was upgraded.

## 1. Identity

| field | value |
|---|---|
| branch | `staging` |
| HEAD at the start | `618f5e6ec6913fc41abb0c791c924bc55b6ed4df` |
| worktree at the start | clean (`git --no-optional-locks status --porcelain` empty) |
| `available` readings | see §7; 22–23 GiB for the first builds, 27–29 GiB for the gate runs (`free -g`) |
| court | `openssl-rs-court-tools:1`, re-created at `OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g`, `CARGO_BUILD_JOBS=4`, `--test-threads` as recorded per run |
| source identity of the tests | the working tree at the base plus this change; no candidate DSO was rebuilt and no downstream binary was measured |
| authority | unchanged from `observables.json`; no authority DSO was run for this follow-up |

Every number below is produced by a named in-crate test, so it is reproducible from the
test name.

## 2. What the three outcomes mean here

| outcome | meaning |
|---|---|
| **supported** | the operation is defined, and a named invariant (not a convention) is what makes it safe; a safe program may rely on it |
| **refused** | the operation is answered by a defined error, and the state is left valid, rolled back or explicitly poisoned |
| **outside the contract** | the operation cannot be made safe by the component that receives it; the class-3 disposition is `UB_NOT_CLAIMED_SAFE` and the caller obligation is stated |

A crash, a hang or silent corruption is a finding in every column. One hang was observed
during this work and is recorded in §5.1.

## 3. The contract table

| # | callback class | outcome | established by |
|---|---|---|---|
| 1 | destructor **mutates** the stack during `OPENSSL_sk_pop_free` (push/insert) | **supported**, with a recorded ownership consequence | `runtime::stack::tests::a_destructor_may_push_onto_the_stack_and_the_destruction_set_is_the_entry_snapshot` |
| 2 | destructor **releases** the same stack (`sk_free` / `sk_pop_free`) | **outside the contract** — class 3 | `runtime::stack::tests::a_destructor_that_releases_the_owning_stack_is_outside_the_contract` |
| 3 | destructor frees an object a **later destructor** of the same run will touch (sibling dependency) | **outside the contract** — class 3 | `runtime::stack::tests::a_sibling_revoked_by_an_earlier_destructor_is_still_delivered` |
| 4 | RNG callback re-enters decryption for the **same object mid-initialisation** | **supported** (defined refusal) | `rsa::ossl::tests::a_reentrant_call_for_the_mid_initialisation_object_is_refused`; combined arm in `a_first_use_rng_callback_may_reenter_rsa_decryption` |
| 5 | RNG callback re-enters decryption for a **different object** | **supported** | `rsa::ossl::tests::a_first_use_rng_callback_may_reenter_rsa_decryption` (second arm) |
| 6 | RNG callback **destroys** the object whose first-use secret is being drawn | **supported** at the KDK helper and at its entry point, with the invariant in §4.4 | `rsa::ossl::tests::an_rng_callback_that_destroys_the_object_publishes_nothing` |
| 7 | **another thread** destroys the object during initialisation | **supported** (defined refusal) | `rsa::ossl::tests::destruction_during_initialisation_is_a_defined_refusal` |
| 8 | panic in a destructor during `OPENSSL_sk_pop_free` | **refused**: leak, never a second destruction | `runtime::stack::tests::a_panic_at_the_first_middle_and_last_destructor_leaks_only_the_remainder`; `a_panic_during_pop_free_leaves_no_reachable_element_and_a_retry_is_safe` |
| 9 | a peer waits on an initialiser whose RNG callback never returns | **refused** at the bound (`WaitTimedOut`) | `rsa::ossl::tests::a_peer_wait_that_is_never_satisfied_is_the_bounded_timeout` |

## 4. Each row, its invariant and the observed behaviour

### 4.1 Mutation during destruction — supported, with a leak

The invariant is the HAZ-16 detach: `OPENSSL_sk_pop_free` takes the whole element array
with `core::mem::take` **before the first callback**, so the destruction set is a snapshot
and the stack is a live, empty stack for the whole run. A destructor that inserts is
therefore operating on a different object from the one being iterated; it cannot disturb
the iteration, and no borrow held by `pop_free` is aliased.

Observed: three elements, each destructor inserts one marker. The insert answers
`1`, `2`, `3` in destruction order — the pushes really happened on the live stack — every
snapshot element is released exactly once, and **no inserted marker is released**
(`released == 0` for all three). The consequence is ownership, not safety: the inserted
elements are not part of the destruction set, and because the enclosing call releases the
stack when it returns, they are **leaked**. A caller must not insert into a stack it is
destroying and expect the insertion to be destroyed; it must own those elements itself.

### 4.2 Recursive destruction — outside the contract

The enclosing call releases the `OPENSSL_STACK` **after** the last destructor
(`src/runtime/stack.rs`, the single `Box::from_raw` at the end of the body). A destructor's
`sk_free`/`sk_pop_free` on the same stack would therefore be the **first** of two releases
of one allocation. The pinned authority has the same defect in a worse form: its loop
indexes `st->num`/`st->data` after the destructor has freed them.

Classification: the register's class-3 example *"a callback that frees the object it runs
on"*, disposition `UB_NOT_CLAIMED_SAFE`. **A caller must not release a stack from one of
its own destructors.** Making it safe would require the component to distinguish "release
requested while my own loop is running"; that is a change to the shared owner whose
release body HAZ-16's differential and ordering evidence is bound to, so it is recorded
here as an open obligation for HAZ-16 rather than repaired under HAZ-15.

The control demonstrates the request without performing the second release: a test-only
release canary records any release requested for the stack whose own `pop_free` loop is
still on the frame and withholds it, so the enclosing call performs the single release.
Observed for both `sk_free` and `sk_pop_free`: one recursive attempt, the canary fires,
all three snapshot elements are destroyed exactly once, and the test itself is
well-defined. The canary is `#[cfg(test)]`, inert unless armed, and absent from release
builds.

### 4.3 Sibling invalidation — outside the contract

`pop_free` delivers every element of its snapshot, in order, with no inspection of the
element or of its owner. A destructor that frees an object a later destructor will touch
therefore hands that later destructor a dangling pointer, and the stack cannot detect it —
there is no ownership information in `const void *`.

The control revokes the two later elements from the first destructor (by a flag, so the
test stays well-defined) and records delivery: `(0, false), (1, true), (2, true)` — the
stack delivers the revoked siblings anyway, in snapshot order. **A caller must give each
element independent ownership (or its own reference); it must not free another element
from a destructor, and must not push two owners of one object without a reference count.**

### 4.4 Re-entrant decryption for the object that is mid-initialisation — supported

The store's lock is not held across `RAND_priv_bytes`, and the owner of an `INITIALIZING`
reservation is recognised by thread identity, so a callback that re-enters the same object
receives `ReentrantInitialization` **immediately** instead of waiting on itself (which
would deadlock: the wait is on a reservation only that thread can publish).

Observed: the outer first use completes (`1`), the inner call answers `0` and the internal
refusal is `ReentrantInitialization`, the object ends with exactly one `Ready` entry, no
`INITIALIZING` entry, and a later use of the object returns the **same** key material as
the outer call — the published secret is the outer call's.

### 4.5 Destruction from the callback — supported, with a named invariant

The callback releases the only reference to the object whose secret is being drawn.
`RSA_free` runs `destroy_body`, whose first step is `forget_ext_kdk_secret`, so the
reservation is removed before the callback returns; the outer publication matches no
reservation and is refused. Observed: the call answers `0`, no entry survives, and a fresh
object completes its first use on the same store.

The invariant that makes it safe is three-part and each part is in the code:

1. `per_key_ext_kdk_secret` reads the object **only** as an address (`let key = rsa as
   usize`), never dereferences it, and the reservation records that address;
2. `derive_external_kdk` returns the refusal **before** reading `(*rsa).libctx`, because
   the refusal is produced by the `?` on `per_key_ext_kdk_secret`, not by the KDF;
3. `rsa_ossl_private_decrypt` performs no field access of `rsa` after
   `derive_external_kdk` returns `0` — it leaves the `'body` block and releases its own
   `BN_CTX` and buffer only.

**Retained obligation.** Part 3 is an invariant of the current entry-point body, not of a
type: any future field access of `rsa` after the KDK call would break it. The entry point
itself is not exercised end to end here because reaching the RNG through
`rsa_ossl_private_decrypt` needs an engine-backed key (`RSA_FLAG_EXT_PKEY` with a
`rsa_mod_exp` method), which this crate cannot construct without an `ENGINE`; the control
drives `derive_external_kdk`, the function that contains the defect and the only caller of
`per_key_ext_kdk_secret`. This is the same limitation the previous re-entrancy evidence
records.

### 4.6 A peer wait that is never satisfied — refused at the bound

The wait is bounded by `EXT_KDK_WAIT_LIMIT` (5 s), so a peer that arrives while an
application RNG callback is parked is not an unbounded wait on that callback. Observed:
the peer refuses with `WaitTimedOut` after 5.01 s, the owner's reservation is not consumed
by the refusal, and releasing the callback then publishes the one secret and returns the
entry count to zero. The control's own result waits are 10 s, so a regression that removes
the store's bound fails the control rather than hanging it.

## 5. Panic injection

### 5.1 The first-use secret path, five sites

`rsa::ossl::tests::a_panic_at_each_fallible_step_leaves_no_entry_and_the_next_attempt_succeeds`
injects one panic per run at:

| stage | site |
|---|---|
| `AfterReserve` | the reservation is installed and its guard exists, the store's lock already released |
| `AfterDraw` | `RAND_priv_bytes` succeeded; the secret is held in a `SecretBuf`, unpublished |
| `DrawFailureAbandon` | the draw failed and the failure path is about to return through the guard |
| `PublishBeforeInstall` | publication has found its reservation, under the store's lock, and has not installed the secret |
| `PublishAfterInstall` | the secret is installed `Ready` and the guard is not yet marked published |

For every stage: the panic propagates out of the initialiser, no `INITIALIZING` entry
survives, no secret survives, a later attempt answers `1` and installs exactly one
`Ready` entry, and the release leaves no entry. The two publication stages panic while
the store's lock is held, which poisons it; `lock_ext_kdk_store` recovers the guard from
the poison, so the later attempt succeeds. **Poisoning is tolerated, not repaired**, and
that is the observable this control records.

**Finding (F1), repaired.** The first run of this control **hung** at `AfterReserve`: the
`ExtKdkReservation` guard was declared before the store's `MutexGuard`, so unwinding
dropped the guard first, and the guard's `Drop` took the same non-reentrant lock that the
frame still held. The window contained no panic-capable operation in the base code, so
the defect was latent rather than reachable from a current call — but it made "no panic
may occur between the reservation and the lock release" a **hidden** obligation, and a
hidden obligation is a STOP condition. Repaired by construction:

* `reserve_ext_kdk_entry` now returns the guard and builds it as the last step of the
  reservation, after the entry is installed, with no panic-capable operation between the
  two;
* `per_key_ext_kdk_secret` releases the store's lock immediately after the reservation
  returns — before any statement that can panic — so every later panic point runs the
  guard with no lock held.

The control now runs the whole loop on a worker thread and receives one message per
stage, so a reintroduced deadlock fails the control at a bounded 10 s wait instead of
hanging the suite.

**Finding (F1a), recorded.** The abandonment itself is only reachable from the guard's
`Drop`; a panic inside `Drop` while unwinding would abort the process, so it is not
injectable. What is injected instead is the failure path that *drives* abandonment
(`DrawFailureAbandon`), which is the obligation that matters. A panic in the guard's own
body remains `NOT_RUN` and is named as such.

### 5.2 `OPENSSL_sk_pop_free`, every destructor position

The panic hook is now parameterised by the destructor index (`arm_pop_free_panic_after`),
so the leak-not-double-free behaviour is checked at the **first, a middle and the last**
destructor of a five-element stack
(`a_panic_at_the_first_middle_and_last_destructor_leaks_only_the_remainder`):

| panic after destructor | released | not released | stack after | retry |
|---|---|---|---|---|
| 0 (first) | 1 | 4 | alive, `sk_num == 0`, `sk_value(0)` NULL | frees the stack, destroys nothing |
| 2 (middle) | 3 | 2 | alive, empty | same |
| 4 (last) | 5 | 0 | alive, empty | same |

`panics_caught()` advances by exactly one at each position, so the unwind really was
caught at the FFI boundary. Releasing the stack is the outer call's obligation and it is
not performed by the interrupted call; the retry performs it and invokes no destructor.

## 6. Findings summary

| id | finding | disposition |
|---|---|---|
| F1 | the reservation guard dropped before the store's lock was released: a panic there deadlocks on the non-reentrant mutex | **repaired**; the control proves it at `AfterReserve` and by construction at every other point |
| F1a | a panic inside the guard's own `Drop` aborts and cannot be injected | recorded; `NOT_RUN`, with the driving failure path injected instead |
| F2 | a destructor that releases its own stack is a second release of one allocation | **outside the contract**, class 3, `UB_NOT_CLAIMED_SAFE`; open for HAZ-16 |
| F3 | elements inserted during destruction are not destroyed and are leaked by the release | **recorded behaviour**; the caller owns them |
| F4 | the destruction set is the entry snapshot, so a destructor cannot add to it | **by design**; this is what makes F1's class safe |

## 7. Bounds, and what was measured when

Every wait in the added controls is bounded: peer waits use the store's 5 s
`EXT_KDK_WAIT_LIMIT`, worker results cross an `mpsc` channel read with
`recv_timeout(10 s)`, and each focused court invocation of a test ran under
coreutils `timeout` with an explicit limit (the full-suite runs under
`timeout 3000`). The one observed hang (§5.1) is the finding that motivated the
repair; it was diagnosed with `timeout 90` so it could not hang the suite.
diagnosed with `timeout 90` so it could not hang the suite.

`free -g` was read before every build (all inside the court, one heavy command at a
time). Recorded `available`: 23 GiB at the start (`MemAvailable: 24213376 kB`), 22 GiB
before the court was re-created at a 6g cap (the pre-existing container was 8g), 22 GiB
before the first build, 24 GiB before the retried build, 25 GiB before the focused runs,
23–26 GiB during diagnosis, 27 GiB before `fmt`/`clippy`, and 28–29 GiB before the two
full-suite runs. The first builds therefore ran at 22–23 GiB, below the 24 GiB line of
`AGENTS.md` §6.1(2); the cap used is the value that same section's formula derives for
that availability (`min(8 GiB, available − 16 GiB) = 6 GiB`), and the later gate runs were
above the line.

## 8. What this does not establish

* No sanitizer, Miri or Loom run covers `OPENSSL_sk_pop_free`, the store, or the
  re-entrancy controls. All are `NOT_RUN`.
* The entry point `rsa_ossl_private_decrypt` is exercised only up to the KDK helper (no
  engine-backed key is constructible here), so §4.5's part 3 is established by reading
  the body, not by execution.
* Timing and constant-time behaviour of the first-use path are not measured.
* The returned-length channel of HAZ-15 is untouched, so no hazard or obligation status
  changes: `HAZ-15` stays `CLAIMED_NO_EVIDENCE` and `OBL-RSA-EXTKEY-ORACLE` stays open.
* The test-only hooks added to `src/runtime/stack.rs` change that file's source identity.
  HAZ-16's differential probe (`evidence/haz-16/run_stack_order_probe.sh`) was not
  re-run against this tree; it is `PENDING` for the next gate that rebuilds the candidate
  DSO. The hook code is `#[cfg(test)]` and cannot affect a release binary.
