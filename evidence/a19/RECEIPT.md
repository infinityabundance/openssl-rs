# A19 receipt — authenticated corrections and retractions

## 1. Identity of this batch

| field | value |
|---|---|
| item | A19 (authenticated corrections and retractions: append-only, bound, propagating; preserve what was believed and what was disproved) |
| branch | `staging` |
| HEAD at the start | `6bf8c80aa9419addc85998f21a0c3010e697c4b3` (`a18: an old signature never authorises a stale release`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 28 12 0 5 17` (total 45, used 28, free 12, available **17** GiB); `Swap: 45 36 9` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool or evidence modified |

The machine had 17 GiB available, below the 24 GiB floor AGENTS.md §6.1 sets
before a build. No build was needed or run: every gate is Python-only. The
derived cap would have been `min(8, 17 - 16) = 1 GiB`, below the 2 GiB floor,
so **no new court was started**. The already-running court has a hard 6 GiB cap
and was reused, as A7-A18 did. The command was Python-only and one at a time; no
Rust source was compiled. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/corrections.py` | 1,461 lines | the event model, the 16 refusal codes, the log chain, `append`, `verify`, `current`, `propagate`, `derive_dependents` and the CLI |
| `forensics/tools/tests/test_corrections.py` | 709 lines | 51 controls: one per code, a two-correction chain, a fork, a cycle, a retraction propagating and a dependent left valid, a spurious invalidation, the canonical chain digest, the real log round trip, determinism, CLI exit codes and document synchronisation |
| `docs/CORRECTIONS.md` | 336 lines | the normative document, including the real log, all 16 codes and the non-claims |
| `evidence/a19/build_evidence.py` | 1,501 lines | deterministic producer of the four records |
| `evidence/a19/EVENTS.json` | record | the real log: 11 subjects, 22 events, digest-chained and `SELF_ISSUED` |
| `evidence/a19/PROPAGATION.json` | record | 14 real dependents, their citations and `INVALIDATED` state |
| `evidence/a19/STATUS.json` | record | per subject: outcome, authentication, recorded-as, where the original is preserved |
| `evidence/a19/CONTROLS.json` | record | 16 `control-only` controls over the 16 codes, plus 2 positives |
| `docs/ETP-TODO.md` | 1 row | the A19 row replaced from `TODO` to `DONE`; no other row touched |
| `evidence/a19/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `EVENTS.json` | `f19f38ad46ff24f92d1f3a6c76c3d08db3b33e37803031cad1a66a3fa9b0e89a` |
| `PROPAGATION.json` | `982054f9fb76777e6672137006c0b9388bc0d8c0245eda5638859cdd3d6d78f3` |
| `STATUS.json` | `fcc465dbccc74f2dbc34b12aef1392899e49b740fd3585f0f065d1b1a62439bb` |
| `CONTROLS.json` | `a3f5c76d26f7b458b26f623d82d4bca82e09f7827c7e3b5cf12be33d15944960` |

## 3. The rule

> A correction is a new, bound event. The original is never edited. Everything
> that cited the old value is marked invalidated, and both what was believed and
> what was disproved remain readable.

A silent edit keeps the new value and loses the fact that the project once
believed something else. This item makes the correction a first-class record:
an append-only chain per subject, a binding to the exact original, a propagation
check over the records that cite the superseded digest, and a `current` view that
returns the accepted event **and** the full history. A retracted subject has no
accepted value and keeps its history.

## 4. The event model and the chain

An event is
`{eventId, kind: assert|correct|retract, subject, supersedes: {previousEventId,
previousDigest}, reason, oldValue, newValue, recordedAt, recordedBy: {role,
identity}, evidence, authentication, signature}`. A value carries its own
SHA-256, a citation literal and the digest of the record that carried it. A
correction binds **both** the predecessor event digest and the exact original
value digest.

`assert` records what was believed; `correct` records a successor value;
`retract` records that the subject now has no accepted value. A different value
for an existing subject is a correction, not a new assertion; a different subject
is a new assertion, not a correction.

The log carries a `history` witness (the canonical digest of every stored event,
including its signature) and a `logDigest` over the history. An edit, deletion or
reorder is `CR_REFUSED_HISTORY_ERASED`. A fork (two direct successors of one
predecessor) is `CR_REFUSED_FORK`; a cycle is `CR_REFUSED_CYCLE` and is checked
before fork because a cycle makes its predecessor look forked. One `assert` per
subject, unique `eventId`, and a retraction only of an asserted subject are
enforced.

The role mapping is A19's: `assert` and `correct` require the `producer` role,
`retract` requires the `revocation_authority` role. The identity must already be
assigned that role in `evidence/a14/ROLES.json`. A14 has no correction role and
records **no declared identity**, so the role check is a membership check, not an
authentication.

## 5. The real log and propagation

`EVENTS.json` holds **11 subjects and 22 events**: an `assert` for what was
believed and a bound `correct` or `retract`.

| subject | event | kind | binding (old → new) | authenticated? | recorded as | outcome |
|---|---|---|---|---|---|---|
| `A4/L3-md32-update/byteLength` | `A19-E01`,`E02` | correct | `0xA5` (165) → `0x165` (357) at `5f868b04f` | no | prose-only (`evidence/a4/RECEIPT.md` §6) | `CORRECTED` |
| `gate-reliability/verify-deterministic-projection` | `A19-E03`,`E04` | correct | live `MemAvailable` in the compared record → declared `environment`; `{tmp}` substituted everywhere at `1efd02cbd` | no | prose-only (`evidence/gate-reliability/RECEIPT.md` §3–§5) | `CORRECTED` |
| `A7/sourceIdentity` | `A19-E05`,`E06` | correct | live `HEAD` at `f2d6e379` → explicit identity and 16 input digests at `2a5a3f86` (`f1c5047a5`) | no | prose-only (`evidence/a7/RECEIPT.md` §11) | `CORRECTED` |
| `A11/SCAN.json/population` | `A19-E07`,`E08` | correct | live glob at `9cc6680f` → frozen 386-member list at `0307db34` (`4e9262bf3`) | no | prose-only (`evidence/a11/RECEIPT.md` §12) | `CORRECTED` |
| `A16/INVENTORY.json/populationFiles` | `A19-E09`,`E10` | correct | live glob 407 at `b6c06350` → frozen 404 at `a7e20060` (`2e8e9aa65`) | no | prose-only (`evidence/a16/RECEIPT.md` §11) | `CORRECTED` |
| `HAZ-15/external-key-KDK` | `A19-E11`,`E12` | correct | `SHA-256(decrypted block)` → keyed derivation (`c28ac7bb9`) | no | prose-only (`evidence/haz-15/KDK-CORRECTION.md`; commit message) | `CORRECTED` |
| `HAZ-15/posterior-probability-99.6` | `A19-E13`,`E14` | retract | the unconditional 99.6% posterior → no accepted value (`4cafcd0ea`) | no | prose-only (`evidence/haz-15/REENTRANCY-AND-LENGTH.md` §5.3) | `RETRACTED` |
| `ETP0-CLM-004/verdict` | `A19-E15`,`E16` | retract | `CONTRADICTED` → `SUPERSEDED` | no | machine-readable but unsigned (`evidence/etp/claims.json`; history copy) | `RETRACTED` |
| `ETP0-CLM-005/verdict` | `A19-E17`,`E18` | retract | `CONTRADICTED` → `SUPERSEDED` | no | machine-readable but unsigned | `RETRACTED` |
| `ETP0-CLM-030/verdict` | `A19-E19`,`E20` | retract | `CONTRADICTED` → `RISK_ACCEPTED`; `SAFE_COMPATIBLE` stays `NOT_ESTABLISHED` | no | machine-readable but unsigned | `RETRACTED` |
| `ETP0-CLM-032/verdict` | `A19-E21`,`E22` | retract | `CONTRADICTED` → `SUPERSEDED` | no | machine-readable but unsigned | `RETRACTED` |

**The finding on authentication is the honest result.** Zero events are
authenticated. Seven corrections are `prose-only`; four claim retractions are
`machine-readable-unsigned`; none is `signed`. A14's assignment records declare
no identity for the producer or the revocation authority, and the only signer is
A10's test-only HMAC-SHA256 key.

**Propagation.** `derive_dependents` walks `evidence/`, `docs/`,
`forensics/tools/` and `courts/` for the superseded value digest, the record
digest and the `oldValue.citation`, and records the citation line and the nearest
supersession marker. On the real data it found **14 dependents** across the seven
value/record-bound corrections; all 14 are `INVALIDATED`, with **0 stale** and
**0 spurious**. The dependents are the correcting receipts and the records that
quote both the old and the new value; `docs/ETP-TODO.md` cites three of the
superseded values (A4, KDK, 99.6%) and is `INVALIDATED` for each.

The four claim retractions are bound to the **exact original claim object**
digest in `evidence/etp-t15/history/claims.before-reconciliation.json`, not to
the digest of the file that carries it. The file digest `65d8105b` is shared by
four claims and by every record that cites the claims set as an input; using it
would make the dependency relation meaningless. No downstream record quotes the
old object's digest, so those four events have **no digest-citing dependent**.
The successor is recorded by claim identity in `evidence/etp/claims.json` and in
`docs/ADJUDICATION-RECONCILIATION.md`. That is a negative result, recorded rather
than filled with an invented dependent.

## 6. The controls

`CONTROLS.json` holds **16** `control-only` fixtures over the **16** refusal
codes, plus two positives. Every fixture is synthetic and built by the producer;
the producer refuses to emit a record whose observed code differs from the
declared one.

The required controls are present and named: `fork`, `cycle`, `history-erased`,
`invalidation-not-propagated` (a retraction whose dependent is left valid) and
`spurious-invalidation`. The positives are `retraction-propagates` (the same
retraction with the dependent `INVALIDATED` reaches `CR_OK`) and
`positive-chain` (an `assert → correct → correct` chain verifies and its accepted
event is `CORRECTED`).

What the positives establish: the decision procedure can accept a chain, a
retraction that reaches its dependent, and a correctly invalidated dependent, so
the refusals are not vacuous. What they do not establish: that any real
correction is authenticated, that the marker classifier is complete, or that an
independent party reviewed the log. They are controls, not corrections.

## 7. Defects found

**A defect in an existing record, found by the full suite and not repaired.**
The whole tools discovery is 1,515 tests with **1 failure**, and the failure is
not in A19. `test_omission.Determinism.test_two_runs_and_the_committed_bytes_are_identical`
regenerates `evidence/a17/STATUS.json` and compares it with the committed bytes:

| field | committed (A17) | fresh run at this HEAD |
|---|---|---|
| `cycles.forward.presentToday` | `0` | `1` before this receipt, `2` after it (A18's and A19's receipts) |
| `cycles.forward.missingToday` | `20` | `19` before this receipt, `18` after it |

A18's `RECEIPT.md` landed at `6bf8c80aa` without regenerating the A17
forward-freeze status; the committed record still says nothing is present. The
record is **outside A19's write scope** (`evidence/a17/` is another item's
evidence), so it is recorded here and not repaired, and the check is not relaxed.
The 51 A19 tests pass; no A19 test fails. This is the forward-freeze mechanism
itself showing that A18 and A19 are present while A17's status has not caught up.

**Development corrections, before any record was produced.** No defect was found
in an existing *correction* record: the eight real events are faithful to their
receipts.

* (a) The first cycle control observed `CR_REFUSED_FORK`, because a cycle
  necessarily makes its predecessor look forked. Old: fork checked before cycle.
  New: the cycle walk runs before the fork check, so the cycle control observes
  `CR_REFUSED_CYCLE` and the separate fork control still observes
  `CR_REFUSED_FORK`.
* (b) The first marker scan classified the A16 and gate-reliability receipts
  `VALID`, because their supersession is stated as "old and new identity" and
  "the earlier inference", seven to eight lines from the citation. Old: ±6-line
  window, no `old and new`/`preserved`/`before and after` markers; the real
  propagation reported two stale dependents. New: ±10-line window and the three
  markers; both receipts are `INVALIDATED`, and the real data reports 0 stale.
  The old and new classifications are preserved here because the classifier is a
  reported classification, not a proof.
* (c) The producer's failure path referenced the caught exception variable
  outside its `except` block. Old: `refusalMessage` read a deleted name. New: the
  code and message are captured before the fallback; the producer reports a
  refusal instead of crashing.
* (d) A separate `CORRECTIONS.envelope.json` was written at first; the envelope
  is already inside `EVENTS.json` as `logEnvelope`, so the duplicate was removed
  to keep the evidence to the four records the item specifies. This is a scope
  trim, not a correctness change.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 28 12 0 5 17` (available 17 GiB); `Swap: 45 36 9` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1515 tests in 238.812s`; `FAILED (failures=1)`; `closure discipline self-test: 7 control groups passed`. The 1,464 pre-existing tests are present (1,464 + 51 = 1,515), none ignored, none removed. The one failure is the A17 record staleness in §7, not an A19 test |
| focused A19 controls | `python3 -m unittest forensics.tools.tests.test_corrections` | `Ran 51 tests in 5.015s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on the four records | `json.tool ok EVENTS.json`, `PROPAGATION.json`, `STATUS.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a19/build_evidence.py --out /tmp/a19a` and the same to `/tmp/a19b` | `a19: subjects=11 events=22 corrected=6 retracted=5 disputed=0 unknown=0 authenticated=0 proseOnly=7 machineReadableUnsigned=4 dependents=14 invalidated=14 stale=0 spurious=0 controls=16 codes=16 commit=6bf8c80aa` twice |
| producer byte-identity | `cmp` of each name, run1 vs run2 vs committed | `identical run1=run2=committed EVENTS.json`, `PROPAGATION.json`, `STATUS.json`, `CONTROLS.json` |
| CLI, real verify | `python3 forensics/tools/corrections.py verify` | `verify: code=CR_OK events=22 subjects=11 outcomes=CORRECTED,RETRACTED`; every subject `history=2`; exit 0 |
| CLI, real propagate | `python3 forensics/tools/corrections.py propagate` | `propagate: code=CR_OK dependents=14 invalidated=14 valid=0 supersededDigests=15`; every dependent `state=INVALIDATED`; exit 0 |
| CLI, history | `python3 forensics/tools/corrections.py history A7/sourceIdentity` | `history: code=CR_OK subject=A7/sourceIdentity outcome=CORRECTED accepted=A19-E06 events=2`; exit 0 |
| worktree | `git --no-pager status --porcelain` | see §12 |

## 9. Obligations retained

* **No event is authenticated.** The only key is A10's test-only HMAC-SHA256 key,
  symmetric and recorded inside the candidate tree. A14 declares no identity. A
  signature proves byte integrity, not identity or role.
* **The dependent classifier is reported, not proved.** The token scan finds a
  record that quotes the old digest, value or citation. A record that relies on
  the value in a form the scan does not recognise is not found. The real data
  found 14 dependents and 0 stale; that is not a proof that no stale record
  exists.
* **The four claim retractions have no digest-citing dependent.** Their successor
  is recorded by claim identity, not by the old object's digest.
* **History-erasure detection is relative to the log's own chain.** A rewriter who
  recomputes the chain and re-signs with the public test key is not detected. An
  external anchor is A16/B1-B5's subject.
* **The old value was not always committed.** For A4, gate-reliability and the
  99.6% posterior, the pre-correction record existed only in the working tree; the
  correcting receipt is the only preservation, and it is prose.
* **A19's role mapping is not an authority.** A14 has no correction role; the
  mapping decides which assigned role may record which kind. It creates no
  identity, key or grantor.
* **A17's forward-freeze status is stale.** A18's and A19's receipts are present
  but the committed `evidence/a17/STATUS.json` still says none is. The repair
  belongs to A17's owner and is outside A19's write scope.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.
* **The forward freeze is open.** This item satisfies its one declared member;
  the freeze itself is not closed and is not evidence that the other items are
  done.

## 10. `NOT_RUN`

* An authenticated correction event: none exists. A14 declares no identity, and
  the only signer is the test-only HMAC key.
* A real independent recorder, reviewer or adjudicator of a correction: none.
* A production key, a key ceremony, key distribution or an external trust root:
  none exists.
* A wall-clock, RFC 3161 or transparency-log timestamp for the log or an event:
  none is configured.
* A repair of a stale dependent: none was found on real data. The 14 dependents
  are all `INVALIDATED`, and the four claim retractions have no digest-citing
  dependent; that is a negative result, not a proof of completeness.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite: no Rust
  source was modified, so no rebuild and no `cargo test` is claimed.

## 11. Forward-freeze members

`evidence/a17/FREEZE-forward.json` declares **one** A19 member:

* **satisfied:** `a19-receipt` — `evidence/a19/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

Still open under the same freeze (18 members, not this item's work):
`a20-receipt` … `a27-receipt` (8 remaining, A20-A27), `b0-registry`,
`b0-service-configuration`, and `b1-receipt` … `b8-receipt` (8). The freeze
remains `state: OPEN`; it was not amended and not closed, and this receipt does
not claim any of those members. A18's member was satisfied before this item;
A19's presence is the second, which is why the A17 status in §7 now reads two
present against the committed zero.

## 12. Worktree

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
?? docs/CORRECTIONS.md
?? evidence/a19/
?? forensics/tools/corrections.py
?? forensics/tools/tests/test_corrections.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row (A19);
`git diff --stat` reports one insertion and one deletion for that file.

## 13. Correction (2026-11-25): the log envelope is re-signed over moved inputs

**Cause.** Two of this record's declared inputs moved in the same batch. A11's
and A16's correction sections were appended to `evidence/a11/RECEIPT.md` and
`evidence/a16/RECEIPT.md` (the author-identity rewrite and the claim-schema
extension moved their candidates and populations), and this producer records the
SHA-256 of every input in `sourceIdentity.inputs` and seals the log with a DSSE
envelope over its canonical bytes. The envelope therefore had to be re-derived;
it was not hand-edited.

**Old and new.**

| field | old | new |
|---|---|---|
| `sourceIdentity.inputs[3].sha256` (`evidence/a11/RECEIPT.md`) | `a548c427f9ef5fac1a0e91b1d3612547eb834e2eb8d288e5a2d3d69b207227a4` | `af99fd9cab3d458a363cfd1728160a05e1c5bf40fa9502cf0e27113461a67eb9` |
| `sourceIdentity.inputs[4].sha256` (`evidence/a16/RECEIPT.md`) | `b0d6a67fcc9db58247eedac3686aa693be154baeff5d65ef80a8a3aabf7f73a9` | `d50464cd8ffb77b5fbb37aff653ee246e9ab7e97d9d9b3f75c97197e08d51d85` |
| `EVENTS.json` | `f19f38ad46ff24f92d1f3a6c76c3d08db3b33e37803031cad1a66a3fa9b0e89a` | `e362777c4825ec76bd38572d9aabaaea9a969a3dbe2dd4ac61b3b58ef330f5c4` |
| `STATUS.json`, `PROPAGATION.json`, `CONTROLS.json` | — | byte-identical |

The change is confined to `sourceIdentity.inputs[3]`, `sourceIdentity.inputs[4]`,
`logEnvelope.payload` and `logEnvelope.signatures[0].sig`
(`5FO6liZOaVvtF0FGWe3TvHo8NZzZvE9XItpltoT2Yns=` →
`0yaDApNytI15yeqrZSeecHpzuy+QQWp3+PhIRY0DhKQ=`). Every event, every event
signature, `logDigest`, the 22 events, 14 dependents and 16 controls are
unchanged: a recursive `json.loads` comparison of the two documents reports four
differing leaves, all in the envelope or in those two input digests.

**Failing tests.** None of this item's tests failed; the correction is forced by
its inputs, and `test_corrections.Determinism.test_two_runs_are_byte_identical_and_match_committed`
would have failed if the record had been left at the old input digests.

**Retained.** The log is still `SELF_ISSUED` and unauthenticated; the signature
still proves bytes unchanged since signing, not an independent recorder; a
reconstruction of a prose or unsigned record is still not an assertion by the
party it describes.

## 14. Correction (2026-11-25): the identity moves to C7 after the A7 repair

**Cause.** Commit `9193603682cf` ("A7 and B8: repair two records that did not
match what their checks observe") rewrote `evidence/a7/RECEIPT.md`
(`8c00cd7a…` → `9adb6775…`) and `evidence/a7/BASELINES.json` (`2a5a3f86…` →
`a57a2766…`). A19 records `evidence/a7/RECEIPT.md` as
`sourceIdentity.inputs[2]`, and this batch regenerates the record at candidate
`ed2143d5a…` (C7), so `sourceIdentity.baseCommit` moved with it. The envelope was
re-derived over the new canonical bytes; it was not hand-edited.

**Old and new.**

| field | old | new |
|---|---|---|
| `sourceIdentity.baseCommit` | `6bf8c80aa9419addc85998f21a0c3010e697c4b3` | `ed2143d5ac6c2266dcba60dad65be2572dc4c03f` |
| `sourceIdentity.baseCommitShort` | `6bf8c80aa` | `ed2143d5a` |
| `sourceIdentity.inputs[2].sha256` (`evidence/a7/RECEIPT.md`) | `8c00cd7aabe8bb1aba0c47981f581fd7aa709452d65fdee66ebd8b88a797efd5` | `9adb6775e0f4e4f9b7ab6cca240de342b6250572606403c06bdf3a9373c2b01d` |
| `EVENTS.json` | `e362777c4825ec76bd38572d9aabaaea9a969a3dbe2dd4ac61b3b58ef330f5c4` | `7df3ca2774ad17b823b995c6ae5ea4b79673f55b1ea4f8b73f3fe08fe305ac63` |
| `PROPAGATION.json` | `982054f9fb76777e6672137006c0b9388bc0d8c0245eda5638859cdd3d6d78f3` | `892be6ef2d394e7724f29563cb993778d844f90349c6325a0f195279e5003278` |
| `STATUS.json` | `fcc465dbccc74f2dbc34b12aef1392899e49b740fd3585f0f065d1b1a62439bb` | `6c732e50b8b7cdda21477a761c1169c93280c5715c2b0015fe37cea620957a97` |
| `CONTROLS.json` | `a3f5c76d26f7b458b26f623d82d4bca82e09f7827c7e3b5cf12be33d15944960` | `039666052b4b8d0591f026a2836df22384d35b2bbbce71e3efb0f7fec6120f79` |

The change is confined to each record's `candidate.baseCommit` /
`candidate.baseCommitShort` (all four carry the candidate), the two
`sourceIdentity` fields and the input digest, plus `EVENTS.json`'s
`logEnvelope.payload` and `logEnvelope.signatures[0].sig`
(`0yaDApNytI15yeqrZSeecHpzuy+QQWp3+PhIRY0DhKQ=` →
`NS623OleyqNP+wG9P9Q7/DNuGnUFBWSXBUEDSodKBoA=`). Every event, event signature,
`logDigest`, the 22 events, 14 dependents and 16 controls are unchanged.

**Preserved as history.** `A7_OLD_DIGEST` `f2d6e379…` and `A7_NEW_DIGEST`
`2a5a3f86…` (the A7 values as they stood at `f1c5047a5`) and the
`A7/sourceIdentity` preservation `sha256` `8c00cd7a…` are event history and were
not rewritten. Only the machine-read `sourceIdentity` and the changed input's
digest moved. The later `a57a2766…` BASELINES value belongs to A7's own record;
A19 does not restate it as its own observation.

**Signing identity.** Unchanged: the existing A10 test-only HMAC-SHA256 signer,
keyid `test-only:hmac-sha256:8e10a5a15d233d54`, derived from the fixed public
`TEST_ONLY_SEED` in `forensics/tools/dsse.py`. No new key or signer was
introduced. `forensics/tools/corrections.py verify` reports `code=CR_OK`.

**Failing tests.** Before this correction,
`test_corrections.Determinism.test_two_runs_are_byte_identical_and_match_committed`
failed on the `evidence/a7/RECEIPT.md` input digest. Because `PROPAGATION.json`
moved with the candidate, the A20 decision's `A19.retraction-propagated`
obligation (which pinned `982054f9…`) and A11's frozen population now name
superseded A19 bytes. Those are the next links, not repairs made here.

**Retained.** The log is still `SELF_ISSUED` and unauthenticated, with zero
independent verifications; the signature still proves only bytes unchanged
since signing.

## 15. Correction (2026-11-25): the identity moves to C20 after the A0 F06/F10 repair

**Cause.** Commit `f45cacbd2ccd` (C20, "A0 F06 and F10: stop presenting functional
coverage as consumer status") rewrote `evidence/etp7/RECEIPT.md`, which A19
records as `sourceIdentity.inputs[10]` (`b7b6edef…` → `bbac152d…`). The candidate
moved to C20 in the same regeneration. `evidence/a7/RECEIPT.md` is unchanged at
`9adb6775…`, so A7's own event facts are untouched. The records were re-derived
by the producer; the envelope was not hand-edited.

**Old and new.**

| field | old | new |
|---|---|---|
| `sourceIdentity.baseCommit` | `ed2143d5ac6c2266dcba60dad65be2572dc4c03f` | `f45cacbd2ccd3b7804e16cdbc804c2cb9b373060` |
| `sourceIdentity.baseCommitShort` | `ed2143d5a` | `f45cacbd2` |
| `sourceIdentity.inputs[10].sha256` (`evidence/etp7/RECEIPT.md`) | `b7b6edefbe8ecd6b85742f38bfb2bb8530a3403e7ecd0d3c58f22e03e74dcf4f` | `bbac152d9235a66d380ce0a0ed2d7dbe572e81c046a80fdacce246e3c4da175b` |
| `EVENTS.json` | `7df3ca2774ad17b823b995c6ae5ea4b79673f55b1ea4f8b73f3fe08fe305ac63` | `d779168c8786ec9bd735d66a5efc804ddd0f2104937d0fd55256c357c52e479e` |
| `PROPAGATION.json` | `892be6ef2d394e7724f29563cb993778d844f90349c6325a0f195279e5003278` | `bc476f73e4d6ca9b3bd97b430c59c9dc60be973b43ed9db234060f0402de4dab` |
| `STATUS.json` | `6c732e50b8b7cdda21477a761c1169c93280c5715c2b0015fe37cea620957a97` | `033880573c9529e6ff281fe5c033a720cdb44e0c4c9de48292e4a7eb327731b9` |
| `CONTROLS.json` | `039666052b4b8d0591f026a2836df22384d35b2bbbce71e3efb0f7fec6120f79` | `3b24f73b267f2e726e40b34e8edc4447a806ac63c8a239bdbdbb7e1d96cf596c` |

The four records move because each carries `candidate.baseCommit` /
`candidate.baseCommitShort`; `EVENTS.json` also carries the input digest and
`logEnvelope.payload` + `signatures[0].sig`
(`NS623OleyqNP+wG9P9Q7/DNuGnUFBWSXBUEDSodKBoA=` →
`fbAKaXKeavAncestY6MIVIR+pzmQnyS6do7tvyldVAQ=`).

**Preserved as history (verified byte-equal before and after).**

| subtree | digest (canonical SHA-256) |
|---|---|
| `EVENTS.logDigest` | `869dc595721d626848e240ebc237496dbf74156057522a0c070802617ad620fd` |
| 22 events (and all 22 event signatures, `history`, `authentication`) | `ca2a375090c327b51e420e30a49086653cad5e02ab56f8f208783f595da120ee` |
| `PROPAGATION.dependents` (14) | `9b9879765ea4d01e7b8a1e72f86db25a8e7648f51f5075cb5d3a6005b1a958cb` |
| `PROPAGATION.events` | `9eba6f64b9b23ec1b6279339f648d0050a1da73700f9651ed998237f2614de2d` |
| `CONTROLS.controls` (16) | `70276ef3f6a98d9a62ddbd088b8ec2374b6292832e27bb4a9cea37b056855598` |
| `STATUS.subjects` | `9eb83a0468082ea370d4177d7e5b46edcf4f8aee47ae7b50d973ecbdb77f12a2` |
| `A7/sourceIdentity` events | `3dce79e2afa7b4f06c23ffc4fed3a24eba0b75807c296806ba32fab757601cc7` |

`A7_OLD_DIGEST` `f2d6e379…`, `A7_NEW_DIGEST` `2a5a3f86…` and the preservation
`sha256` `8c00cd7a…` are unchanged event history.

**Signing identity.** Unchanged: the existing A10 test-only HMAC-SHA256 signer,
keyid `test-only:hmac-sha256:8e10a5a15d233d54`, from the fixed public
`TEST_ONLY_SEED` in `forensics/tools/dsse.py`. `corrections.py verify` reports
`code=CR_OK` and `corrections.py propagate` reports `code=CR_OK` (14 dependents,
14 invalidated, 0 valid).

**Downstream.** A20's `A19.retraction-propagated` obligation (which pinned
`892be6ef…`) and A11/A16/A21's frozen populations and summaries now name
superseded A19 bytes. Those are the next links, not repairs made here.

**Retained.** `SELF_ISSUED`, unauthenticated, zero independent verifications.
