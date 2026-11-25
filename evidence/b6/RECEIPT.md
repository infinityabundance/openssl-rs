# B6 receipt — a withdrawn claim is not an erased claim

## 1. Identity of this batch

| field | value |
|---|---|
| item | B6 (`docs/ETP-ADDENDUM-B.md` §B.17, §B.19, §B.30): durable evidence reconstruction, current-state metadata, authenticated correction and anti-rollback; a withdrawn claim refused by current-state policy while its original inclusion proof stays valid |
| status | **`PARTIAL`** — the archive, the derived current state, the policy, the anti-rollback rules and the three-fact demonstration are implemented, controlled and ran; the admitted-log, authenticated-correction and independent-archive halves do not exist in this venue |
| branch | `staging` |
| HEAD at the start | `19b710192` (`b3: freeze the reconciliation at its declared commit`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 38 4 0 2 7` (available **7** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, `HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944` (6 GiB), repository bind-mounted at `/work`; **reused, not restarted** |
| interpreter | CPython 3.11.2 in the court |
| heavy commands | one at a time; no Rust build |

Available memory was below the 24 GiB floor `AGENTS.md` §6.1 sets before a build.
No build was needed or attempted: every gate is Python. The derived cap
`min(8g, available − 16g)` is negative, below the 2 GiB floor, so **no new court
was started**; the existing 6 GiB court was reused and every command ran inside
it. `docker/` was not modified and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/archival.py` | 1,603 | the archive reader and reconstruction, the derived state, the policy, the anti-rollback rules and the `current`/`inclusion`/`reconstruct`/`derive`/`admit`/`use`/`compare` CLI; 14 `RV_REFUSED_*` codes plus `RV_OK` |
| `forensics/tools/tests/test_archival.py` | 648 | 59 controls: one per refusal code, reconstruction both ways, state monotonicity and the three anti-rollback refusals, the three facts together, determinism, CLI exit codes, document synchronisation |
| `docs/ARCHIVAL-REVOCATION.md` | 319 | the normative document: withdrawal is not erasure, the archive contract, the current-state contract and its version, the anti-rollback rule, the demonstration, the refusal table, non-claims, `NOT_RUN` |
| `evidence/b6/build_evidence.py` | 997 | the deterministic producer of the fixture, the archive, the state, the demonstration and the controls |
| `evidence/b6/ARCHIVE.json` | 200 | the 9 members with digests, the two state identities, the claim, and the reconstruction result |
| `evidence/b6/CURRENT-STATE.json` | 200 | the derived version-22 index: 11 subjects, its digest and its `previous` link |
| `DEMONSTRATION.json` | 82 | the three facts in one record, each with its record and code, and the replayed-version refusals |
| `evidence/b6/CONTROLS.json` | 905 | 15 `controlOnly` rows, one per refusal code plus a positive, each with a restoration |
| `evidence/b6/FIXTURE-2.json` | 124 | the fixture log: leaves, leaf index, inclusion proof, signed checkpoint, labels |
| `evidence/b6/ARCHIVE/MANIFEST.json` | 95 | the archive's own manifest, digest `5d0508b3…` |
| `evidence/b6/ARCHIVE/members/` | 9 files | the member bytes, each hashed in the manifest |
| `docs/ETP-TODO.md` | 1 row | the B6 row changed from `TODO` to `PARTIAL` at base `19b710192`; no other row touched |
| `evidence/b6/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `ARCHIVE.json` | `20c9900f06541affa8a1b0bca141cbb9cd04416bd61ba035032b0db683df7ed5` |
| `CURRENT-STATE.json` | `b16aefb88f01aa53788c6c2abdb35402e1cded16def1d75ce604ee019526eccd` |
| `DEMONSTRATION.json` | `2522aec12c4b80a7e55447867cab505090dfc7d95b24d49428ec5bcc5900baea` |
| `CONTROLS.json` | `44b8ac298a08265bd54968b965b21481f2c79d9026a21c67d7340441eb77d945` |
| `FIXTURE-2.json` | `a1552329f10ae6a897dacbff02d658aa85ed6cf2dca819cca6b101dfa251de02` |
| `ARCHIVE/MANIFEST.json` | `af6d6d3c79bc3e342284f58a9e59e4565049a633a406330d25f67b3e07aba51d` |

## 3. The archive and the current state

### 3.1 The archive

`b6-archive-1` has **9 members**: the fixture statement (leaf 1), the real frozen
A9 statement (leaf 0), the size-5 signed checkpoint, the inclusion proof, the leaf
list, the publication record, the A19 event identities, and the two state
versions. `ARCHIVE.json` records every member's `{id, path, bytes, sha256, role}`
and the manifest digest `5d0508b3…`.

Reconstruction reads only the archive directory and runs 9 checks:
`member-digests`, `manifest-digest`, `checkpoint-signature`,
`publication-record`, `leaf-identity`, `inclusion`, `tree-root`,
`statement-binding`, `state-link`. It verifies the note signature, the origin and
size, the leaf and its hash, the RFC 6962 proof against the checkpoint root, the
root recomputed from the archived leaf hashes, the statement's subject digest
against the archived assertion identity and its `retractedBy` against the
archived retraction identity, and the current state's `supersededBy` /
`correctionDigest` / history against both. A missing member is
`RV_REFUSED_ARCHIVE_MISSING`; a changed byte, an unbound manifest or any failed
verification is `RV_REFUSED_RECONSTRUCTION_MISMATCH` / `RV_REFUSED_ARCHIVE_INVALID`.

The A19 events are archived as **event identities by canonical digest**, not as
copies; see §5.1 for why, and the document for the limit this states.

### 3.2 The current state

Derived from `evidence/a19/EVENTS.json` through `corrections.append`/`current`.
The version is the number of A19 events covered; version **21** still records the
claim `ACTIVE`, version **22** records it `WITHDRAWN`. The index covers 11
subjects: **0 `ACTIVE`, 6 `CORRECTED`, 5 `WITHDRAWN`**. `CURRENT-STATE.json` is
the version-22 document, digest
`31b94d5ea2dbd1dd2fc888b5242e0834d3ef77130a6c8d02aa9e29066c641671`; its
`previous` names version 21, digest
`d5219cea5926efbba82262517d3f02210c16e5157a5f7ef1fc48a89a1f62dcfd`.

The withdrawal is A19's `A19-E22` (event digest `bf4f5320…`), recorded by the
`revocation_authority` role and **`machine-readable-unsigned`**: the only signer
is A10's test-only HMAC key and A14 declares no identity.

### 3.3 The three facts, in one record

`FIXTURE-2` publishes leaf **1** of a five-leaf RFC 6962 log with a 3-element
inclusion proof and a size-5 checkpoint, root
`4b9b97a480f49511bd52f57b68112fdd64d014fbb25bae6aa4cd7f07004946d6`, signed by
A10's test-only HMAC-SHA256 key.

| fact | result |
|---|---|
| `inclusionStillValid` | `RV_OK` — leaf 1, size 5, 3 proof elements, root `4b9b97a4…`, verified from the archive |
| `currentIsWithdrawn` | `RV_OK` — `WITHDRAWN`, version 22, `supersededBy` `A19-E22`, `correctionDigest` `bf4f5320…` |
| `presentTenseRefused` | `RV_REFUSED_WITHDRAWN_ACCEPTED` — the message names `A19-E22` |

### 3.4 The replayed version

The version-21 state is genuine, and it still says `ACTIVE`.

| attempt | result |
|---|---|
| admit version 21 as current, against version 22 | `RV_REFUSED_REPLAY_AS_CURRENT` |
| version sequence 22 → 21 | `RV_REFUSED_ROLLBACK_OF_STATE` |

That is the item: the old record is not forged, it is *not current*, and the
inclusion proof of the original statement still verifies.

## 4. Controls

`evidence/b6/CONTROLS.json`: **15 `controlOnly` rows, 15 fired, one per refusal
code plus a positive**. Each records the mutation, the code and message observed,
and a restoration replay. 13 restorations are acceptances. Two are not ordinary:

* `withdrawn-used-as-current` is *accepted* in the present tense at version 21.
  The row states the scope: this is exactly the replay the anti-rollback rule
  refuses, so the record does not hide the fact that the old state says `ACTIVE`.
* `subject-not-indexed` has no possible acceptance; the row records the control
  subject instead and says so.

Every mutation is on a temporary copy; no control mutates a tracked file.

## 5. Defects found

### 5.1 The first archive made A19's live record stop reproducing (repaired here)

The first build archived the two A19 events as **verbatim members**. A19's
`derive_dependents` scans every `.json`/`.md`/`.py`/`.txt` under `evidence/`,
`docs/`, `forensics/tools/` and `courts/` and classifies any file containing a
*superseded value digest* as a dependent. A faithful copy of the original event
contains that value digest, so the scan added `evidence/b6/ARCHIVE/members/…`
as a dependent and `evidence/a19/PROPAGATION.json` stopped reproducing. The
whole-suite gate caught it:

```
FAIL: test_two_runs_are_byte_identical_and_match_committed (test_corrections.Determinism...)
AssertionError: ... : PROPAGATION.json
Ran 2377 tests
FAILED (failures=1)
```

Cause: the scan has one exclusion for the original record (`evidence/a19`) and no
way to extend it to another directory, so a copy of the *original* is
indistinguishable from a record *citing* it.

**Old:** events copied verbatim into the archive; one new dependent row; A19's
record did not reproduce.
**New:** the archive stores the A19 event identities (event id and canonical event
digest); no superseded value digest is written anywhere in `evidence/b6/`; state
entries do not carry the later-superseded value digest. A19's tool and record were
**not** modified, no exclusion was added and no check was relaxed; the record
reproduces again and the suite is green. The consequence — the archive binds the
claim to the A19 event *digests*, and re-deriving an event digest from its bytes
needs `evidence/a19/EVENTS.json` — is stated in the document's non-claims and in
`NOT_RUN`.

### 5.2 No defect in another item's records was found

A19's `STATUS.json` and `corrections.current` were compared for all 11 subjects:
same outcome and same accepted event id for every one, 0 disagreements.
`docs_consistency.py` and `spec_guard.py check` exited 0 before and after the
edits. `evidence/b3/RECONCILIATION.json` still reports the `b6-receipt` member
missing **at its frozen commit** `1155843e6`, which is correct for a record
frozen before this batch; its live view was not re-run (B3's owner). That
staleness was already recorded by B5 and is not new here.

### 5.3 Defects in this item's own machinery, preserved

A control that passes for the wrong reason is the defect this item exists to
catch, so the development defects are kept:

1. **The producer ran the controls before writing the state.** The
   `state-unreadable` control's restoration read
   `CURRENT-STATE.json` before the file existed and failed with
   `RV_REFUSED_IO`. Old: controls before the write. New: the state is written
   first and the control reads it; the refusal is now only the control's own.
2. **`--check` compared files the producer does not write.** It compared
   `build_evidence.py` against a rebuild and reported it missing. Old: every
   file under `evidence/b6/`. New: only the generated records and the archive.
3. **`archival.py reconstruct` printed no check count.** The shared printer
   skipped the key `checks` because one result carries a list under that name.
   Old: no `checks=` field. New: `checks=9`; the printer skips only non-scalars.
4. **The earlier state carried the withdrawn value digest.** Fixed by the design
   change in §5.1; the state now carries the event digest only.

## 6. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | `Mem: 45 38 4 0 2 7` (available **7** GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect openssl-rs-court` | `mem=6442450944 memswap=6442450944 status=running` (6 GiB), `/work` bind-mounted; reused, no new court, no build |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2377 tests in 470.499s`; `OK`. The **2,318 pre-existing tests are present** (2,318 + 59 = 2,377), none removed, none skipped, none newly ignored |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on every created JSON | `ARCHIVE.json ok`, `CURRENT-STATE.json ok`, `DEMONSTRATION.json ok`, `CONTROLS.json ok`, `FIXTURE-2.json ok`, and `json.tool archive members ok: 9` (the 9 member JSONs including `MANIFEST.json`) |
| 5. producer, twice | `python3 evidence/b6/build_evidence.py` twice, then `diff` of every produced file's SHA-256 | `BYTE-IDENTICAL-RUNS`; run 2: `code=RV_OK b6: version=22 earlier=21 state=WITHDRAWN leafIndex=1 root=4b9b97a4…4946d6`; `code=RV_OK b6: members=9 checks=9 controls=15 codes=RV_OK,RV_REFUSED_ARCHIVE_INVALID,…,RV_REFUSED_WITHDRAWN_ACCEPTED manifest=5d0508b3…` |
| 5. producer check | `python3 evidence/b6/build_evidence.py --check` | `code=RV_OK b6: check ok files=15 version=22 root=4b9b97a4…4946d6 manifest=5d0508b3…`; exit 0 |
| 6. current | `python3 forensics/tools/archival.py current` | `code=RV_OK version=22 asOf=2026-11-23T00:00:00Z digest=31b94d5e… subjects=11 active=0 corrected=6 withdrawn=5`; exit 0. With `--subject ETP0-CLM-032/verdict`: `subjectState=WITHDRAWN supersededBy=A19-E22 correctionDigest=bf4f5320…` |
| 6. inclusion | `python3 forensics/tools/archival.py inclusion` | `code=RV_OK subject=ETP0-CLM-032/verdict leafIndex=1 treeSize=5 leafHash=eaf72570… root=4b9b97a4… verified=True checkpointSize=5 signatureName=FIXTURE-2 test-only hmac-sha256 manifestDigest=5d0508b3…`; exit 0 |
| 6. reconstruct | `python3 forensics/tools/archival.py reconstruct` | `code=RV_OK archiveId=b6-archive-1 members=9 checks=9 leafIndex=1 treeSize=5 root=4b9b97a4… subject=ETP0-CLM-032/verdict subjectState=WITHDRAWN version=22`; exit 0 |
| 6. codes fired by the real run | the three commands above | `RV_OK` on all three; **no refusal code fires on the real archive, state or policy**, which is the expected positive result |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/ARCHIVAL-REVOCATION.md`; `?? evidence/b6/`; `?? forensics/tools/archival.py`; `?? forensics/tools/tests/test_archival.py` — nothing else |

The full discovery ran on the final code, document and record tree.  Only the
prose of this receipt was edited afterwards (a line count, a duration and a
digest), and neither change is read by any test.  B6's 59 controls pass.

## 7. Obligations retained

* **An archive is one copy.** It is not an independent mirror, and a consistent
  rewrite of the archive, manifest and states is not detected. §B.17's
  independently verifiable mirror does not exist here.
* **The A19 binding is by digest.** The event bytes are not archived; re-deriving
  an event digest from its bytes needs `evidence/a19/EVENTS.json`.
* **The log is a fixture.** No Rekor service, client, log key, witness or
  integrated time; the checkpoint is signed by a public test-only HMAC key.
* **The fixture statement is not an A9 attestation.** No A9 predicate type covers
  an A19 subject; the statement is labelled and is not submitted to `intoto.py`.
* **The withdrawal is not authenticated.** No A14 identity, no external trust
  root; `SELF_ISSUED` is the honest state.
* **The current state is not signed metadata.** It has a version and an
  anti-rollback rule but no role separation, expiry or timestamp; an adversary
  who rewrites it and keeps the version increasing is not detected.
* **The subject set is A19's.** A claim A19 never logged has no current state.
* **The producer is the validator.** No independent reviewer ran.
* **The 14 refusal codes are exercised by controls, not by a real adversarial
  archive.** A refusal that fires proves the check works.

## 8. `NOT_RUN`

* A public or admitted transparency log and any inclusion in one.
* A witness or cosignature for the size-5 checkpoint (B5 records 0 witnesses).
* A trusted RFC 3161 timestamp for the publication, the state or the correction
  (B2 records no authority).
* An authenticated correction or withdrawal, a key ceremony or an external trust
  root.
* An independent archive, mirror, monitor or reviewer.
* Re-deriving an A19 event digest from archived event bytes (the bytes are not
  archived; see §5.1).
* Repair or live re-run of `evidence/b3/RECONCILIATION.json` (outside this item's
  write scope; B3's owner).
* `BOUNDARY`, `SEAL` and the Rust suite: no Rust source was modified, so no
  `cargo` command ran.

## 9. Forward-freeze member and worktree

The A17 forward-freeze member `b6-receipt` (`evidence/b6/RECEIPT.md`, predicate
"a receipt records archival, revocation and anti-rollback controls") is
**satisfied**: this receipt and the five records name the archive, its digests,
the derived state and version, the three facts, the replay refusals and the
controls. The freeze itself was not closed, and A20's
`A17.forward-freeze-closed` obligation is unaffected.

Worktree after this batch: `M docs/ETP-TODO.md`;
`?? docs/ARCHIVAL-REVOCATION.md`; `?? evidence/b6/`;
`?? forensics/tools/archival.py`; `?? forensics/tools/tests/test_archival.py`.
Nothing else. This subagent did not commit and did not push.

**Why `PARTIAL`:** the property is demonstrated against a fixture and a derived
state, but no admitted log, authenticated correction, witness, timestamp,
independent archive or independent reviewer exists here, and the A19 binding is
by digest rather than by archived event bytes.

## 10. Correction (2026-11-25): re-derive at C9 after the A19 re-freeze

**Cause.** A19 was regenerated at `f34e429f13aa` (C8), which moved its
`sourceIdentity.baseCommit` from `6bf8c80aa9419addc85998f21a0c3010e697c4b3` to
`ed2143d5ac6c2266dcba60dad65be2572dc4c03f` and its `evidence/a7/RECEIPT.md`
input from `8c00cd7a…` to `9adb6775…`. `archival.derive_state` embeds
`log["sourceIdentity"]` in `derivedFrom`, so both state members moved, and every
record that digests those members followed. The records and the archive were
re-derived by `evidence/b6/build_evidence.py`, not hand-edited.

**Old and new.**

| file | old (HEAD before this correction) | new |
|---|---|---|
| `ARCHIVE/members/state/current-state-21.json` | `d9d352440637bbf7e5d61b060d1f755805cd3a544d42a3672367617983176dff` | `187dd9bcee6570d1fbf75f4c8f7d53c1a6eb11177bd67bfb37b90c15341920ab` |
| `ARCHIVE/members/state/current-state-22.json` | `0da8b4a4780ca807d84764e34bee2287bd23af0688588ec5eee6165379cc15af` | `dfb56e6dd992d6e0ac08fc8e821b1cb9c620c3e4875e389f707d4c8153a054da` |
| `ARCHIVE/MANIFEST.json` | `9c3381cf4ee8da5d5eee892de4a5495d7285927005cff8de4907afa747f43480` | `93b7bd4d0e76d484c47327d3daadd5d0a9d7a0ebd1e02bd741494f8843c9072f` |
| `manifestDigest` | `c2b595a3cb7d2fd3ddbe61075e7803a3f134d7c3ba7727f8b9134f169e5d62e4` | `d09400c474bc21a58f01bcbd6e5c55c8fefb9e3f840767a9ec29004d6cf0a586` |
| `state.earlier.digest` | `624936bb3f4daa8e37c691b9032e26f6420fb194a5abbd7b4e38c2637f3cf2c5` | `9ee0eeb4a3beb42cc97cea3d107244be67389d87442156ecb78c839201ab7e69` |
| `state.current.digest` | `87e30885138d234934b0effb700d75119304041765b19e76b657126145967c9a` | `2c95ecd35afbc4d47f7061bf5eb40fcbee9a431f9505272faa61d40de7eaabb4` |
| `ARCHIVE.json` | `3b0087b7b13292a711d6419aeee8de6a0c97bcd170385baef6f26d48f1fc8475` | `35f34ddfd3a26c075946774b436253492c0981650271f020d7e3af7a8405eee3` |
| `CURRENT-STATE.json` | `0da8b4a4780ca807d84764e34bee2287bd23af0688588ec5eee6165379cc15af` | `dfb56e6dd992d6e0ac08fc8e821b1cb9c620c3e4875e389f707d4c8153a054da` |
| `DEMONSTRATION.json` | `35fa590fb1223e11a49d01409d9a12eb48d654f3edda3b9e2fbe6d1c9f8b5877` | `cfce2b8e96badabab1870c8b30cf3dc542e84713af9ab65b22a0d985fbc2a6f7` |
| `CONTROLS.json` | `c6d6f136756d9b1778ee4abd1b0b274507a875bcbe026c6300d55c02ed77def1` | `de074a99efda4ab42db9572cb391d8ebcac0c608fdfac420e76bafb06d837300` |
| `FIXTURE-2.json` | `a1552329f10ae6a897dacbff02d658aa85ed6cf2dca819cca6b101dfa251de02` | byte-identical |

**Outcome unchanged.** The state is still version 22, the earlier state still
version 21, `ETP0-CLM-032/verdict` is still `ACTIVE` then `WITHDRAWN`, all 11
subject entries and their histories are identical, the inclusion proof is still
leaf 1 of a size-5 tree with root `4b9b97a4…4946d6`, all 9 reconstruction checks
pass, and all 15 controls still fire. Only `derivedFrom.sourceIdentity`, the
state digests computed over it, and the members that record those digests moved.

**History.** The digests in §3–§6 and the `sourceIdentity` `6bf8c80aa…` remain
this batch's original values; §10 supersedes them by naming both values rather
than overwriting the history.

## 11. Correction (2026-11-25): re-derive at C22 after the C21 A19 re-freeze

**Cause.** A19 was re-frozen at `a1c3fa61b4c2` (C21, at candidate
`f45cacbd2ccd`), moving `sourceIdentity.baseCommit` from `ed2143d5ac6c…` to
`f45cacbd2ccd…` and its `evidence/etp7/RECEIPT.md` input from `b7b6edef…` to
`bbac152d…`. `archival.derive_state` embeds `log["sourceIdentity"]` in
`derivedFrom`, so both state members moved and every record that digests those
members followed. The producer reads `evidence/a19/EVENTS.json` from the working
tree and does not inspect git; the records and archive were re-derived, not
hand-edited.

**Old and new.**

| file / field | old (HEAD before this correction) | new |
|---|---|---|
| `ARCHIVE/members/state/current-state-21.json` | `187dd9bcee6570d1fbf75f4c8f7d53c1a6eb11177bd67bfb37b90c15341920ab` | `38caea3607f9151c7f533fdf039bb5b0968929c05c764681753e09fb264bc8ee` |
| `ARCHIVE/members/state/current-state-22.json` | `dfb56e6dd992d6e0ac08fc8e821b1cb9c620c3e4875e389f707d4c8153a054da` | `3d19787c1cdef88d293c6accb1ff0c5ea38d80bfc843d9fa3b267a6c5d264d21` |
| `ARCHIVE/MANIFEST.json` | `93b7bd4d0e76d484c47327d3daadd5d0a9d7a0ebd1e02bd741494f8843c9072f` | `f825bbea618d3a3873ace30815717b9c8f5394ec065b57f345680d0c1674e115` |
| `manifestDigest` | `d09400c474bc21a58f01bcbd6e5c55c8fefb9e3f840767a9ec29004d6cf0a586` | `5bd0bd6462b36a4b2b66666f8e13bba0b769d36e52255c7c9c30d1768128a6f8` |
| `state.earlier.digest` | `9ee0eeb4a3beb42cc97cea3d107244be67389d87442156ecb78c839201ab7e69` | `1de32afacef2e6f9784b2cd900ab25e34e2028840099e8a4497ce645859bac68` |
| `state.current.digest` | `2c95ecd35afbc4d47f7061bf5eb40fcbee9a431f9505272faa61d40de7eaabb4` | `f451f878a2f1000ec7a013b184fdf9a3410cb28112ac885f7d80a7992c79bdb3` |
| `ARCHIVE.json` | `35f34ddfd3a26c075946774b436253492c0981650271f020d7e3af7a8405eee3` | `965ae5b099a7cd5c97a2aec57c9f9e80aca3fe6c989c4bf69d1ed9efee6197ef` |
| `CURRENT-STATE.json` | `dfb56e6dd992d6e0ac08fc8e821b1cb9c620c3e4875e389f707d4c8153a054da` | `3d19787c1cdef88d293c6accb1ff0c5ea38d80bfc843d9fa3b267a6c5d264d21` |
| `DEMONSTRATION.json` | `cfce2b8e96badabab1870c8b30cf3dc542e84713af9ab65b22a0d985fbc2a6f7` | `3554db0fb06ea87536d1c660018cbcf6bc211c7d5246cedf619f4814f0f9ec61` |
| `CONTROLS.json` | `de074a99efda4ab42db9572cb391d8ebcac0c608fdfac420e76bafb06d837300` | `153af2942fb78e5f70c1653c813f3f8962d3da45feea76fd6ece34dbcadb1177` |
| `FIXTURE-2.json` | `a1552329f10ae6a897dacbff02d658aa85ed6cf2dca819cca6b101dfa251de02` | byte-identical |

**Outcome unchanged.** The state is still version 22, the earlier state still
version 21, `ETP0-CLM-032/verdict` is still `ACTIVE` then `WITHDRAWN`, all 11
subject entries and their histories are identical, the inclusion proof is still
leaf 1 of a size-5 tree with root `4b9b97a4…4946d6`, all 9 reconstruction checks
pass, and all 15 controls still fire. The log members (checkpoint, inclusion
proof, leaf list, publication, both statements and the A19 binding) are
byte-identical. Only `derivedFrom.sourceIdentity`, the state digests computed over
it and the records that cite those digests moved.

**History.** The digests in §3–§6 and §10 remain the earlier batches' record; §11
supersedes them by naming both values rather than overwriting the history.

**Gates.** `python3 evidence/b6/build_evidence.py` exits 0 with `version=22
state=WITHDRAWN leafIndex=1 root=4b9b97a4…4946d6 members=9 checks=9`;
`test_archival` is 59/59 OK.

**Gates.** `python3 evidence/b6/build_evidence.py` reproduces the committed
bytes and prints `code=RV_OK b6: version=22 earlier=21 state=WITHDRAWN`;
`test_archival` is 59/59 OK. The archive is still a fixture derivation (see §7),
so re-deriving it is not a rewrite of history: its own control requires the
committed members to equal the derivation from the current A19 log.
