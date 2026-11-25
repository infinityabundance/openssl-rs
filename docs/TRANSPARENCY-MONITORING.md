# Transparency monitoring: persistent checkpoints, consistency and witnesses

**Status of B5: `PARTIAL`.** The monitoring half is implemented and ran offline
against the B1 fixture's real checkpoint sequence. The witness half is
`NOT_RUN`: no witness, no witness key, no independent operator domain and no
network exist in this venue.

| half | what it is | status |
|---|---|---|
| **monitoring** | an append-only checkpoint store, signature and consistency verification over time, split-view and rollback refusal, tamper evidence | ran against `FIXTURE-1` |
| **witnesses** | admission of a quorum of independently established operator domains | **`NOT_RUN`** (0 witnesses, 0 quorum, 0 independent domains) |

The implementation is `forensics/tools/monitor.py`; its controls are
`forensics/tools/tests/test_monitor.py`; the records are
`evidence/b5/MONITOR.json`, `evidence/b5/WITNESSES.json`,
`evidence/b5/CONTROLS.json` and `evidence/b5/store/monitor-store.jsonl`,
produced deterministically by `evidence/b5/build_evidence.py`.

This document is normative for both halves. It does not upgrade the witness
half: a recorded quorum is not a met quorum, and a monitor is not a witness.

---

## 1. What monitoring can and cannot establish

Offline, against a sequence of signed heads, monitoring **can** establish:

* that each recorded head was produced from a note whose body parses as the
  pinned checkpoint form;
* that each head carries a signature by the policy-selected key over its exact
  bytes;
* that the recorded sequence is **append-only** — no size decreases, no two
  accepted heads at one size carry different roots, no origin changes;
* that each larger head is **consistent** with the last accepted one, because
  the RFC 6962 consistency proof reconstructs both authenticated roots;
* that observations are ordered, and that a checkpoint observed before the last
  accepted observation is refused;
* that the store itself has not changed since it was written, because every
  record names its predecessor and carries a digest over its own bytes.

It **cannot** establish:

* that the log operator is honest, or that the head it served this monitor is
  the head it serves anyone else;
* that **no other view of the log exists**: a split view is detectable only when
  both heads reach this monitor (`MN_REFUSED_SPLIT_VIEW` is local evidence of
  equivocation, never proof of its absence);
* that a checkpoint was **included** in any public log, or that a timestamp is
  trustworthy (§B.9; B2 records no timestamp authority);
* that a witness exists, or that a witness-dependent property holds;
* **complete observation**: a monitor that has observed only a subset of a log
  cannot assert complete global observation (§B.12). The fixture is one log's
  six-leaf tree, not a public log.

**Enforced by** `MONITOR.json#/nonClaims`, `MONITOR.json#/notRun`, and
`test_monitor.FixtureSequence` / `test_monitor.DocumentSynchronisation`.

---

## 2. The store and its tamper evidence

The store is `evidence/b5/store/monitor-store.jsonl`: one JSON object per line,
in observation order. Each record carries the six required fields and the
bookkeeping that makes editing detectable:

| field | meaning |
|---|---|
| `origin` | the checkpoint origin (the log identity) |
| `treeSize` | the authenticated tree size |
| `rootHash` | the authenticated root, lower-case hex |
| `signature` | the policy key's note signature tag, lower-case hex |
| `observedAt` | the monitor's observation instant, explicitly zoned |
| `source` | where the checkpoint came from |
| `noteSha256` | SHA-256 of the exact signed note the record was made from |
| `seq` | 1-based position |
| `prev` | the previous record's `digest`, or 64 zeros |
| `digest` | SHA-256 over the canonical JSON of every other field |

Editing any field, dropping a record, reordering two records or splicing one in
changes a `digest` or a `prev` link and is refused as
`MN_REFUSED_STORE_TAMPERED`. An editor who recomputes the whole chain produces
a store that is *self-consistent* but still cannot re-sign the checkpoints with
the policy key; the monitor additionally re-checks the semantic invariants
(non-decreasing size, one root per size, one origin, non-decreasing observation
time), so a rewritten history is refused as `MN_REFUSED_STORE_TAMPERED` even
with a valid chain.

The digest is **not** a signature. It shows that the recorded bytes are the ones
that were written; it does not show who wrote them.

**Enforced by** `MN_REFUSED_STORE_TAMPERED`,
`test_monitor.RefusalCodes.test_store_tampered_digest_and_canary`,
`...test_store_tampered_field_is_caught_by_the_digest` and
`...test_store_dropped_or_reordered_record_is_refused`.

---

## 3. The observation rules, in order

`monitor.py observe` applies its checks in this fixed order, and the order is
recorded in `MONITOR.json#/causalOrder`:

1. **checkpoint** — parse the note body; refuse a body that is not the pinned
   three-line form, a non-canonical size or root, or a size-0 head whose root is
   not SHA-256 of the empty string (`MN_REFUSED_CHECKPOINT`);
2. **signature** — verify the policy key's signature over the exact note text
   (`MN_REFUSED_SIGNATURE`);
3. **origin** — refuse a checkpoint whose origin differs from the store's
   accepted origin or from the caller's expected origin
   (`MN_REFUSED_ORIGIN`);
4. **rollback** — refuse a size smaller than the last accepted size
   (`MN_REFUSED_ROLLBACK`);
5. **split view** — refuse a size that already has a different accepted root
   (`MN_REFUSED_SPLIT_VIEW`);
6. **backdating** — refuse an instant older than the last accepted observation,
   and refuse an observation with no stated offset (`MN_REFUSED_BACKDATED`);
7. **consistency** — for a larger head, require a proof and verify that it
   reconstructs both authenticated roots (`MN_REFUSED_INCONSISTENT`).

A checkpoint that is both backdated and inconsistent refuses
`MN_REFUSED_BACKDATED` first. The consistency check is never skipped on the
accepted path. An equal-size, equal-root checkpoint is a re-observation and is
accepted; an equal-size, different-root checkpoint is the split view.

The checkpoint format, the note signature and the consistency proof are
**reused** from `forensics/tools/tlog.py`; this module does not reimplement the
note format, the hash construction or the RFC 6962 recursion.

**Enforced by** `MONITOR.json#/sequence` (every row carries `code: MN_OK`),
`MONITOR.json#/causalOrder`, and the per-code tests in
`test_monitor.RefusalCodes`.

---

## 4. Consistency over time

The real run grows the fixture tree 2 → 5 → 6:

| transition | proof | result |
|---|---|---|
| size 2 (first observation) | none required | accepted |
| 2 → 5 | `evidence/b1/fixture/consistency-2-5.json` (2 elements) | consistency verified |
| 5 → 6 | `evidence/b1/fixture/consistency-5-6.json` (3 elements) | consistency verified |

A larger head with no proof receives no append-only credit
(`MN_REFUSED_INCONSISTENT`), and that refusal is shown to be attributable: with
the consistency check disabled the same corrupted proof is accepted, which is
exactly the conclusion the check prevents. `monitor` re-checks the recorded
sequence on every invocation; it cannot re-verify the consistency *proof* after
the fact because the store records the verified transition, not the proof bytes.
That limit is stated rather than hidden.

**Enforced by** `test_monitor.FixtureSequence.test_each_growth_records_a_verified_consistency_proof`,
`...test_growth_without_a_proof_is_refused`, and the `inconsistent` control in
`CONTROLS.json`.

---

## 5. The witness contract

A witness set is a list of witnesses, each with `{operator, keyid, domain}`,
plus the domain's establishment record (`domainEvidence`), the key's `expiresAt`
and the witness's signature over the exact checkpoint bytes (`signedNote`).
Admission requires:

* **a witness set at all** — an absent or empty set is
  `MN_REFUSED_NO_WITNESS`; witness admission is then `NOT_RUN`, never met;
* **a signature over the exact checkpoint bytes** — a witness that signs
  different bytes, or for which no key is recorded, is
  `MN_REFUSED_WITNESS_SIGNATURE`;
* **an unexpired key** — an expired, absent or unreadable expiry is
  `MN_REFUSED_WITNESS_EXPIRED`;
* **distinct established operator domains** — the count is delegated to
  `forensics/tools/thresholds.py` (A15), not restated here.

### A quorum is not a threshold of labels

Two labels that resolve to one establishment record are **one** domain, and one
operator under two labels is one domain. The set is refused as
`MN_REFUSED_WITNESS_ALIASED` when labels or identities collapse, and the
labels that collapsed are named. The count is over distinct establishment
records, so `MN_REFUSED_WITNESS_QUORUM` fires when fewer than `k` distinct
operator domains have a qualifying witness.

A signature and an expiry are witness-specific checks that A15 does not perform:
A15 documents that it does not verify signatures and takes `verified` from its
caller. This module supplies that check and then reuses A15's counting rule.

**A quorum is not a threshold of labels, and a label asserted by a witness is
not a domain.** The required quorum recorded here is `k = 3` of `n = 4` on the
§B.11 model that survives one compromised witness; a fixed three-witness
population with a two-witness threshold does not. The quorum is recorded, not
met.

**Enforced by** `MN_REFUSED_NO_WITNESS`, `MN_REFUSED_WITNESS_QUORUM`,
`MN_REFUSED_WITNESS_ALIASED`, `MN_REFUSED_WITNESS_EXPIRED`,
`MN_REFUSED_WITNESS_SIGNATURE`; `WITNESSES.json#/aliasingRule`; and
`test_monitor.WitnessDelegation`.

---

## 6. The real run

The monitor observed the B1 fixture's real checkpoint sequence in order. The
fixture is `FIXTURE-1` (`admittedService: false`, labels `test-only`,
`not-rekor-tiles`, `no-log-key`, `no-witness`, `no-production-signature`); the
signer is A10's fixed public test key, not a log key.

```
observations: 3
sizes: 2, 5, 6
final head: origin FIXTURE-1, size 6,
            root e9a8ad0126e834c0ec34fed464572772d3f3c2d3501198239a1a5554324c540f
store: evidence/b5/store/monitor-store.jsonl
       records 3, bytes 1665,
       sha256 08db31ac2292c11fb93cd4d5169a8823461dac9564a12b5e82900c91b4ae7c5b
witnesses: 0
required quorum: k=3
outcome: NOT_RUN
```

`monitor.py status` prints `MN_OK` with the size-6 head and three observations.
`monitor.py monitor` reports two transitions and a verified chain.
`monitor.py witness` refuses with `MN_REFUSED_NO_WITNESS`.

**Enforced by** `MONITOR.json#/sequence`, `#/finalHead`, `#/status`,
`WITNESSES.json#/observed`, and `test_monitor.FixtureSequence`.

---

## 7. The corrupted controls

Each corrupted sequence is built in memory from the real fixture bytes. Each
refuses with its named code, and each carries a canary showing the same input
accepted when the named check is disabled.

| control | mutation | code | canary |
|---|---|---|---|
| `rollback` | the real size-2 checkpoint after the size-6 head | `MN_REFUSED_ROLLBACK` | accepted with the rollback comparison disabled |
| `split-view` | a signed size-6 head with a different root | `MN_REFUSED_SPLIT_VIEW` | accepted with the split-view comparison disabled |
| `origin` | a correctly signed head whose origin is `OTHER-LOG` | `MN_REFUSED_ORIGIN` | accepted with the origin comparison disabled |
| `backdated` | the real size-6 head observed before the accepted one | `MN_REFUSED_BACKDATED` | accepted with the backdating comparison disabled |
| `store-tampered` | one byte of the first record's chained digest flipped | `MN_REFUSED_STORE_TAMPERED` | read and reported with the store check disabled |

`CONTROLS.json` adds one control per remaining refusal code:

| control | code | canary |
|---|---|---|
| `signature` | `MN_REFUSED_SIGNATURE` | accepted with signature verification disabled |
| `inconsistent` | `MN_REFUSED_INCONSISTENT` | accepted with the consistency check disabled |
| `checkpoint` | `MN_REFUSED_CHECKPOINT` | accepted with the root-validity check disabled |
| `no-witness` | `MN_REFUSED_NO_WITNESS` | **no acceptance exists**; the next refusal is the quorum |
| `witness-quorum` | `MN_REFUSED_WITNESS_QUORUM` | accepted with the quorum comparison disabled |
| `witness-aliased` | `MN_REFUSED_WITNESS_ALIASED` | accepted with the aliasing check disabled (A15 still counts one domain) |
| `witness-expired` | `MN_REFUSED_WITNESS_EXPIRED` | accepted with the expiry comparison disabled |
| `witness-signature` | `MN_REFUSED_WITNESS_SIGNATURE` | accepted with the witness-signature check disabled |
| `usage` | `MN_REFUSED_USAGE` | not applicable: a malformed invocation has no accepted form |
| `io` | `MN_REFUSED_IO` | not applicable: an unreadable path has no bytes |
| `fixture-sequence` | none (positive control) | the real sequence is accepted (`MN_OK`) |

Three canaries cannot accept, and say why. The checkpoint parse is what makes
every other check possible, so a malformed body is refused with
`MN_REFUSED_CHECKPOINT` even with signature, origin and root-validity disabled;
that is an **attribution** canary, not an acceptance. An unreadable path and a
malformed invocation have no bytes or arguments that a disabled check could
turn into a record.

Every witness fixture is `control-only` and synthetic, generated under
`evidence/b5/control-only/`; no witness admission is claimed.

**Enforced by** `CONTROLS.json` (16 rows, `controlOnly: true`, one per refusal
code plus a positive) and `test_monitor.RecordsAndDeterminism` /
`test_monitor.RefusalCodes`.

---

## 8. Refusal table

Each code is stable, and each names the conclusion it prevents.

| code | condition | prevents |
|---|---|---|
| `MN_OK` | the requested operation succeeded | — |
| `MN_REFUSED_CHECKPOINT` | a note is not the pinned checkpoint body, or a size-0 head has a non-empty root | bytes that are not a checkpoint being read as an authenticated head |
| `MN_REFUSED_SIGNATURE` | no signature for the policy key, a wrong key hash, or a signature that does not verify | an unsigned or differently signed head being recorded |
| `MN_REFUSED_ORIGIN` | the origin differs from the accepted or expected one | another log's or shard's head being recorded as this log's state |
| `MN_REFUSED_ROLLBACK` | the size is smaller than the last accepted size | a stale checkpoint replacing a later accepted one |
| `MN_REFUSED_SPLIT_VIEW` | one size carries two different authenticated roots | an equivocating head being accepted as growth |
| `MN_REFUSED_INCONSISTENT` | a larger head has no valid consistency proof against the accepted head | append-only credit without a verified relationship |
| `MN_REFUSED_BACKDATED` | the observation instant is older than the last accepted one, or has no offset | an observation being ordered before an accepted one |
| `MN_REFUSED_STORE_TAMPERED` | a chained digest, link, sequence or schema does not verify, or the recorded sequence violates a monitor invariant | edited bytes being read as the accepted history |
| `MN_REFUSED_NO_WITNESS` | no witness set exists, or it contains no witness | absence of a witness being read as a quorum |
| `MN_REFUSED_WITNESS_QUORUM` | fewer than `k` distinct established operator domains qualify | fewer independent witnesses than the quorum being read as meeting it |
| `MN_REFUSED_WITNESS_ALIASED` | two labels or one operator resolve to one domain | one operator being counted twice |
| `MN_REFUSED_WITNESS_EXPIRED` | a witness key expired, or its expiry is absent or unreadable | an unauthorised key being counted |
| `MN_REFUSED_WITNESS_SIGNATURE` | a witness signature does not verify over the exact checkpoint bytes | a non-signing witness being counted |
| `MN_REFUSED_USAGE` | the command line is malformed or incomplete | a refused invocation being read as an accepted operation |
| `MN_REFUSED_IO` | a required path is absent, unreadable or not a regular file | an unreadable record being read as empty or agreeing |

**Enforced by** `monitor.REFUSALS` and
`test_monitor.DocumentSynchronisation.test_the_document_exists_and_names_every_code`.

---

## 9. Non-claims

* Monitoring shows that **this sequence** of heads is internally consistent and
  append-only; it does not show that the log is honest or that no other view
  exists.
* The monitor observed one fixture; it cannot assert complete observation of any
  log.
* The fixture is not an admitted Rekor service, and the signer is A10's
  test-only key, not a log key.
* The observation instant is the monitor's own record, not a signing time, an
  integrated time or a trusted timestamp.
* A consistency proof relates two heads; it does not show that either was served
  to anyone else.
* No witness, witness key or independent operator domain exists, so witness
  admission is `NOT_RUN`.
* A control that fires proves the refusal works; it does not show the
  substituted form occurs in any log.
* A recorded quorum is not a met quorum.

**Enforced by** `MONITOR.json#/nonClaims`, `CONTROLS.json#/nonClaims` and
`WITNESSES.json#/nonClaims`.

---

## 10. `NOT_RUN`

* Admission of a genuinely independent witness: no witness service, key or
  operator domain exists.
* Observation of a public log, a second view or another monitor's transcript:
  no log and no network.
* An independently operated monitor or an independent reviewer.
* Detection of equivocation that was never served to this monitor.
* A trusted timestamp for any observation (§B.9; B2 records no authority).
* Independent review, `BOUNDARY`, `SEAL` and the Rust suite (no Rust source was
  modified, so no `cargo` command ran).
* Closure of the A17 forward freeze; this item satisfies its `b5-receipt`
  member only.

**Enforced by** `MONITOR.json#/notRun`, `WITNESSES.json#/outcome`, and
`test_monitor.DocumentSynchronisation`.
