# HAZ-16 — stack destruction order, atomicity and linear cost

**Item:** `HAZ-16` / `OBL-PANIC-ATOMICITY`, `OPENSSL_sk_pop_free`.
**Base candidate:** `staging` at `4cafcd0ea` (clean worktree at the start).
**This document:** the stack-order follow-up to the earlier remove-before-release
repair. The earlier repair preserved atomicity but destroyed elements
last-to-first. This follow-up restores the authority's order without giving up
atomicity or linear cost.

## 1. Identity

| item | value |
|---|---|
| source HEAD | `4cafcd0ea7888f789dfb901e754ac22d4d2745de` (`staging`, clean at start) |
| candidate DSO | `court/tmp/haz16/libcrypto.so.3`, SHA-256 `c04d47c290c3c4c97ffbb18559420d85f2c68cc66fcaf29b5f944beec8601089` |
| authority DSO | `forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3`, SHA-256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| authority source | `forensics/authorities/src/openssl-3.6.4/crypto/stack/stack.c:441-457` |
| toolchain | rustc 1.98.1 (`48a229cea`); cc 12.2.0 |
| venue | `openssl-rs-court-tools:1`, 6g/6g cap, probes pinned to CPU 1 |
| probe | `evidence/haz-16/pop_free_order_probe.c` |
| runner | `evidence/haz-16/run_stack_order_probe.sh` |
| transcript | `court/tmp/haz16/RESULTS.txt` |

The candidate DSO and the authority DSO are loaded one per process with
`dlopen(..., RTLD_LOCAL)` and resolved through that handle, so the same probe
drives either implementation without symbol interposition.

## 2. The three properties, and the mechanism

The authority body is:

```c
for (i = 0; i < st->num; i++) {
    if (st->data[i] != NULL) {
        if (st->free_thunk != NULL)
            st->free_thunk(func, (void *)st->data[i]);
        else
            func((void *)st->data[i]);
    }
}
OPENSSL_sk_free(st);
```

It destroys elements first-to-last, but each destructor sees the whole array and
an interrupted call leaves already-released elements reachable.

The candidate body detaches the whole element array before the first destructor:

```rust
let (items, thunk) = {
    let Some(s) = inner(st) else { return };
    let thunk = s.free_thunk;
    let items = core::mem::take(&mut s.items);
    s.num_alloc = 0;
    (items, thunk)
};
for item in items {
    /* skip NULL, invoke thunk or func */
}
drop(Box::from_raw(st as *mut Inner));
```

| property | why it holds |
|---|---|
| authority order | the detached `Vec` is visited with its original index order, 0 to `n-1`, so the callback sequence is first-to-last, exactly as the authority's loop |
| linear time | `mem::take` is O(1) (it replaces the vector with an empty one and moves the three machine words); the loop visits each element once, so the whole operation is O(n) |
| failure atomicity | the stack holds no elements from the moment of the detach, before any callback. No destructor can observe a released element through `sk_num`/`sk_value`, and a retry finds an empty stack |

The `&mut Inner` borrow ends before the loop, so a destructor that re-enters the
stack interface (for example `OPENSSL_sk_num`) does not alias the borrow held by
`OPENSSL_sk_pop_free`. The earlier end-popping shape admitted only the ordering
property; the earlier front-removal shape admitted only order and atomicity at
O(n²). The detach shape admits all three.

## 3. Panic-path behaviour (recorded, not accidental)

The detached array is a local `Vec<*const c_void>`. If a destructor panics,
`guard_ffi` catches the unwind, and the local vector is dropped:

- the vector's storage is deallocated;
- its elements are raw pointers, which have no destructor, so the elements whose
  callbacks had not yet run are **leaked**;
- the already-destroyed elements are not revisited;
- the enclosing stack is not freed by the interrupted call, but it is alive and
  empty, so a retry of `pop_free` frees it and invokes no destructor.

Leaking the unprocessed remainder is the recorded outcome. Double destruction is
excluded, and no released element is reachable.

## 4. Differential destruction order

Same operation, same element identities 0–7, one process per library:

| subject | operation | observed sequence |
|---|---|---|
| pinned authority 3.6.4 | `OPENSSL_sk_pop_free` | `0,1,2,3,4,5,6,7` |
| candidate | `OPENSSL_sk_pop_free` | `0,1,2,3,4,5,6,7` |
| candidate | end-popping loop (`sk_pop`) | `7,6,5,4,3,2,1,0` |
| candidate | front-removal loop (`sk_shift`) | `0,1,2,3,4,5,6,7` |

The candidate's public operation matches the authority exactly. The end-popping
row is the rejected reversal and is the control that the ordering test detects.
The front-removal row keeps order but is the O(n²) shape rejected earlier.

Verbatim from `court/tmp/haz16/RESULTS.txt`:

```
## destruction order
ORDER pop_free 0,1,2,3,4,5,6,7
ORDER pop_free 0,1,2,3,4,5,6,7
ORDER pop 7,6,5,4,3,2,1,0
ORDER shift 0,1,2,3,4,5,6,7
```

## 5. Controls

### 5.1 Ordering test

`runtime::stack::tests::pop_free_destroys_elements_first_to_last` registers
destructors that append their identity to a thread-local log and requires
`[0, 1, 2, 3, 4]`.

- fixed source: **passed**.
- revert control (iterate the detached array with `.rev()`): **failed**

```
assertion `left == right` failed: destruction must follow the authority's first-to-last order
  left: [4, 3, 2, 1, 0]
 right: [0, 1, 2, 3, 4]
```

### 5.2 Invariant control

`runtime::stack::tests::every_destructor_runs_with_the_stack_already_empty`
samples `OPENSSL_sk_num(st)` and `OPENSSL_sk_value(st, 0)` inside every callback.
All three destructors observed `(num = 0, first = NULL)`: **passed**. This
callback re-enters the stack interface, which is legal because the `Inner` borrow
has ended and the stack is alive until after the loop.

### 5.3 Retry control

`runtime::stack::tests::a_panic_during_pop_free_leaves_no_reachable_element_and_a_retry_is_safe`
arms the test-only panic hook (it panics after the first destructor) and then:

- observes exactly one caught panic at the FFI boundary;
- asserts the first element was destroyed once and the other two not at all;
- asserts `OPENSSL_sk_num(st) == 0` and `OPENSSL_sk_value(st, 0) == NULL`;
- retries `OPENSSL_sk_pop_free`, then asserts the three release counts are still
  `1, 0, 0` — the leaked remainder is not destroyed a second time.

Fixed source: **passed**.

Revert control (in-place iteration, the authority's shape): **failed**

```
assertion `left == right` failed: the stack is empty
  left: 3
 right: 0
```

### 5.4 Complexity control

`run_stack_order_probe.sh` times only the destroy path, with a no-op destructor
and pushes outside the timed region, seven samples per size on CPU 1.

Candidate `OPENSSL_sk_pop_free`, minimum nanoseconds:

| elements | 4 000 | 8 000 | 16 000 | 32 000 | 64 000 |
|---:|---:|---:|---:|---:|---:|
| candidate | 4 419 | 8 773 | 17 499 | 34 960 | 69 858 |
| ratio to previous | — | 1.99× | 1.99× | 2.00× | 2.00× |

The doubling at every size is the linear control.

The end-popping shape is also linear but reversed:

| elements | 4 000 | 8 000 | 16 000 | 32 000 | 64 000 |
|---:|---:|---:|---:|---:|---:|
| `sk_pop` loop | 7 316 | 14 586 | 29 149 | 58 227 | 116 383 |

The front-removal shape is visibly superlinear:

| elements | 2 000 | 4 000 | 8 000 | 16 000 |
|---:|---:|---:|---:|---:|
| `sk_shift` loop | 77 697 | 261 015 | 1 789 712 | 10 642 738 |
| ratio to previous | — | 3.36× | 6.86× | 5.95× |

Doubling the element count multiplies the front-removal time by roughly four or
more, while the candidate's path doubles. The pinned authority `pop_free` is also
linear at these sizes (5 337 → 10 142 → 23 752 → 41 745 → 69 843 ns), with more
run-to-run noise than the candidate; the complexity claim here is the candidate's
doubling and its separation from the quadratic control, not a fitted exponent.

The samples are a single pinned process per size with no statistical campaign;
they demonstrate scaling, not a performance boundary. Allocation surveys and
wall-clock ratios are separate obligations (T21/T29).

## 6. Gates

All commands ran in `openssl-rs-court-tools:1` with `CARGO_BUILD_JOBS=4`. The
host readings taken before Rust builds were 24 GiB `available` (the §6.1
threshold) and the court was capped at 6g/6g. Venue deviation: one cached-artifact
probe rerun (`HAZ16_REBUILD=0`) performed no Rust compilation — it relinked the
existing archive, compiled the C probe and ran the samples — and was launched
without a fresh `free -g` reading; the 6g/6g cap was still in force. That rerun
is a measurement convenience, not a gate pass.

```
$ cargo fmt --all -- --check
FMT_EXIT=0
```

```
$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 17.17s
```

```
$ cargo test --lib -- --test-threads=1
test result: ok. 2441 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 443.80s
```

```
$ cargo test --lib -- --test-threads=4
test result: ok. 2441 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 136.69s
```

Baseline was 2439 passed / 0 failed / 54 ignored. The two net new tests are the
ordering test and the invariant test (the panic test was rewritten in place), so
2441 is baseline + 2 / 0 failed / 54 ignored. No test was removed or newly
ignored.

```
$ python3 forensics/tools/hazard_register.py validate
hazard register /work/evidence/etp-t2/HAZARDS.json: 20 hazards, 8 fault trees, 30 FMEA rows, 12 UCAs, 7 attack graphs
barrier states: BARRIER_ABSENT=2, CLAIMED_NO_EVIDENCE=18, EVIDENCED=0; FMEA evidence: CLAIMED_NO_EVIDENCE=23, EVIDENCED=0, NONE=7
BARRIER_ABSENT: HAZ-18, HAZ-20; no release claim: HAZ-05, HAZ-12, HAZ-17
register and traceability graph agree
```

```
$ python3 forensics/tools/traceability.py validate
traceability graph at 21bea318819a56f641b3aa2f25027216b97a1c4d: 358 nodes (...); 469 edges (...)
orphans: 39 declared and reproduced (39 ids), 0 undeclared, 0 stale
```

```
$ python3 forensics/tools/divergence_obligations.py --check
[divergence-obligations] ok: 10 row(s) match the table (0 blocking)
```

```
$ python3 forensics/tools/docs_consistency.py
[docs-consistency] EXEMPT: ...
[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources
```

The `docs_consistency.py` exemption is the pre-existing Phase-7 seal exemption,
unchanged by this batch.

## 7. Limits and non-claims

- Differential order is established for eight elements through one probe on one
  target and toolchain. It is a behavioural comparison, not a proof for every
  caller callback.
- The retry control is deterministic because the test-only hook injects the
  panic. It does not establish what an arbitrary C callback does before it
  returns.
- Leaking the unprocessed remainder on a panic is deliberate and recorded. It is
  not a failure-atomic cleanup of the caller's elements; it is the choice that
  excludes double destruction.
- The timing rows are a scaling control, not a benchmark, and the court is a
  virtualised venue.
- This document does not change `HAZ-16`'s `CLAIMED_NO_EVIDENCE` barrier or
  close `OBL-PANIC-ATOMICITY`: the 744-candidate residual and the
  `evp`/`rsa`/`ec`/`x509` abort path remain outside it.
