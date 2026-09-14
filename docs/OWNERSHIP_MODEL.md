# Ownership Model

Status: **constitution** (Phase 0).

OpenSSL's C API encodes ownership through *conventions*, not the type system.
This is a major source of compatibility defects and therefore gets a dedicated
evidence plane and dedicated courts.

## 1. The conventions

| form | meaning | obligation |
|---|---|---|
| `get0` | borrowed reference | caller must **not** free; pointer valid only while the parent lives |
| `get1` | owned reference, refcount incremented | caller **must** free with the matching free function |
| `set0` | **takes** ownership | caller must not free; callee frees or transfers |
| `set1` | **copies/increments** | caller retains its reference and remains responsible for it |
| `up_ref` | increment refcount | caller takes a new reference |
| `free` | decrement, free at zero | idempotent on `NULL` |
| `dup` | deep or refcounted copy | ownership of the result transfers to the caller |

Null semantics, duplicate semantics, lifetime extension, callback lifetime and
aliasing expectations are all part of the contract.

## 2. Observation over documentation

Ownership is **not** derived solely from documentation when direct observation is
possible. The authority is instrumented:

- **canary allocators** and lifetime probes in oracle processes;
- allocator origin tracking (which allocation a pointer belongs to);
- refcount read-out before and after each call;
- explicit probes establishing, for each call: *takes ownership*, *borrows*,
  *increments*, *duplicates*, *invalidates on parent destruction*, *aliases*;
- duplicate/free edge behaviour, including double-free detection and
  free-after-parent-destroy.

The resulting `forensics/atlas/<authority>/ownership-obligations.json` is
generated, not written by hand, and every record cites the probe that produced
it.

## 3. Candidate internals vs the FFI contract

Candidate Rust internals may use safe ownership patterns (`Arc`, `Box`, owned
structs, lifetimes). This is encouraged.

The **FFI contract must reproduce the C-visible lifetime behaviour**, including:

- a pointer returned by a `get0` accessor remains valid for exactly as long as the
  authority keeps it valid, and not longer;
- a `set0` transfer does not double-free when the caller also releases;
- refcounts are observable through the authority's own APIs;
- freeing a parent invalidates borrowed children in the authority's manner.

Where Rust's model and the C contract disagree, the C contract wins at the
boundary, and the reconciliation is documented in the affected module.

## 4. Courts

A dedicated `MEM-OWNERSHIP` court family exists. Representative obligations:

- every `_get0` / `_get1` / `_set0` / `_set1` / `_up_ref` / `_free` / `_dup`
  accessor in the atlas;
- parent-destruction invalidation, probed with canaries;
- callback lifetime (a callback holding a borrowed pointer);
- aliasing: two accessors returning pointers into the same object.

## 5. Promotion

An ownership obligation is `OWNERSHIP_PASS` only when the candidate's
observable behaviour matches the authority under the probe, including the null
and duplicate edge cases. Matching on the happy path is insufficient: the
defects live in the edges.

`get0`/`set0`/`get1`/`set1` motifs recur across the whole API, so they are also
published as durable precedents (see the Gemel precedent store): a precedent
*proposes* investigation but never decides truth — courts decide.
