# A17 receipt — omission resistance: freeze before execution, close against it

## 1. Identity of this batch

| field | value |
|---|---|
| item | A17 (transparency and omission resistance; the freeze/close half, built beside the existing claim-algebra half) |
| branch | `staging` |
| HEAD at the start | `731b066e261ebc64cf8acb909df18d23b9b11883` (`a16: a bundle carries portable material, not portable trust`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 22 19 0 4 23` (total 45, used 22, free 19, available **23** GiB); `Swap: 45 34 11` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool or evidence modified |

The machine had 23 GiB available, below the 24 GiB floor §6.1 sets before a
build. No build was needed or run: every gate is Python-only. The already-running
6 GiB court was reused, as A7-A16 did. No test was edited, skipped, ignored or
removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/omission.py` | 1,350 lines | `freeze`, `close`, `sign`, `verify`, `check`; 16 stable refusal codes; CLI `freeze`, `close`, `sign`, `verify` |
| `forensics/tools/tests/test_omission.py` | 670 lines | 43 controls: one per code, arithmetic, both directions of `UNREADABLE`/`MISSING`, the two named controls, the real A15 cycle, the forward `OPEN` freeze, determinism, CLI, document synchronisation |
| `docs/OMISSION-RESISTANCE.md` | 273 lines | the normative document for this half; names the claim-algebra receipt and does not supersede it |
| `evidence/a17/FREEZE-a15.json` | 62 lines | the five A15 records, frozen before the re-run, with committed digests |
| `evidence/a17/FREEZE-forward.json` | 162 lines | 20 required members for A18-A27 and B0-B8, `state: OPEN` |
| `evidence/a17/RECONCILIATION-a15.json` | 81 lines | the real closure: 5 expected, 5 `PRODUCED` |
| `evidence/a17/RECONCILIATION-a15.envelope.json` | 3,224 bytes | DSSE envelope over the canonical reconciliation bytes, test-only key |
| `evidence/a17/STATUS.json` | 68 lines | the two cycles, their counts, the forward freeze's `OPEN` state |
| `evidence/a17/CONTROLS.json` | 229 lines | 17 `control-only` controls over 16 codes, plus one positive control |
| `evidence/a17/build_evidence.py` | 724 lines | deterministic producer; re-running reproduces all six records byte-for-byte |
| `docs/ETP-TODO.md` | 1 row | the A17 row replaced from `PARTIAL` to `DONE`; no other row touched |
| `evidence/a17/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `FREEZE-a15.json` | `eb225ec5ae08b6041f7f5df5578166151e475639d6be8ce4f7fa19d2f4fef12f` |
| `FREEZE-forward.json` | `ee62ed9475e2fc940d8b2fbc43d485842a42ac19abd027b528836f7b7997b886` |
| `RECONCILIATION-a15.json` | `c0a4938597e30eb901a11efa1ceaf72c8ca5a67555678a5ab5b8a828c3de4d5f` |
| `RECONCILIATION-a15.envelope.json` | `a36d33fbebab408faa7bb665ecc54a3477988a2a94eace70da42b382ee204048` |
| `STATUS.json` | `8fc514d24829eec50189272ff7001fac4adae6f172f44a58ecdf369bdfa334f5` |
| `CONTROLS.json` | `9cddfc0752b6e58a5b4019a164fd80e34928ccabd95eb0843d95356adcd0cea7` |

## 3. The rule

> Freeze the expected population **before** execution. After execution, account
> for every expected member as `PRODUCED`, `MISSING`, `UNREADABLE` or
> `DIGEST_MISMATCH`, and report every undeclared observation as `UNEXPECTED`.
> A summary may not report success while an expected member is missing, and a
> producer may not shrink the population it is judged against.

The closure is reconciled in a manifest and that manifest is signed. Because the
only signing key in the tree is A10's test-only HMAC-SHA256 key, the signature
proves the manifest's bytes have not changed since signing; it does **not** prove
that an independent party closed it. A12 records every such envelope
`SELF_ISSUED`.

## 4. The freeze contract, the states and the arithmetic

A freeze is `{id, state, candidate, frozenAt, recordedAt, producedBy, members,
memberCount, digest}`. `digest` is over every other field. `memberCount` must be
the length of `members` and is the freeze's only count.

`close` records one state per expected member:

| state | meaning |
|---|---|
| `PRODUCED` | bytes exist at the declared path and the close recorded their digest |
| `MISSING` | no bytes at the declared path |
| `UNREADABLE` | bytes exist but could not be read |
| `DIGEST_MISMATCH` | bytes exist but disagree with the frozen or supplied digest |

The arithmetic is `produced + missing + unreadable + digestMismatch == expected`,
with `unexpected` counted separately. `summary.pass` is true only when every
required member is `PRODUCED` and no `UNEXPECTED` member is present.

`sign` uses A10's `dsse.py` and the exact PAE; this module does not reimplement
it. `verify` requires an envelope, a valid signature over the received bytes, and
a verified payload equal to the canonical bytes of the reconciliation, and only
then checks the closure. A closure of an `OPEN` freeze never passes.

## 5. The two real cycles

**A real closed cycle (backward), A15.** `FREEZE-a15.json` declares the five
`evidence/a15/*.json` records with their ids, paths, predicates and committed
`expectedDigest`, `frozenAt` `2026-11-24T00:00:00Z`. The producer then re-runs
`evidence/a15/build_evidence.py` read-only into a temporary directory and closes
the freeze against the produced bytes. The result is 5 expected, **5
`PRODUCED`**, 0 `MISSING`, 0 `UNREADABLE`, 0 `DIGEST_MISMATCH`, 0 `UNEXPECTED`,
pass. Every produced digest equals the committed digest, and a fresh CLI close is
byte-identical to the committed reconciliation. A15's files were not modified.

**A real forward freeze (forward), A18-A27 and B0-B8.** `FREEZE-forward.json`
declares 20 required members: one receipt per item for A18-A27 (10); B0's
registry and recorded service-configuration finding (2); one receipt per item for
B1-B8 (8). It is recorded `state: OPEN`, has **no** reconciliation and is **not
closed**; `STATUS.json` records `closed: false` and `reconciliation: null`. A
close today reports 20 `MISSING` and pass false, which is expected. The freeze is
the mechanism that will detect a future omission; it is **not evidence that any
of these items is done**.

The two times are declared literals, not clock readings, so the producer is
byte-reproducible. They record the in-process order (freeze, re-run, close), not
a wall-clock measurement. See §9.

## 6. The controls

`CONTROLS.json` holds **17** controls over **16** refusal codes, all
`controlOnly: true`, plus one positive control. Every control is a synthetic
freeze, a synthetic artefact in a temporary directory and a synthetic
reconciliation built from the same code paths the real cycle uses. The two named
controls are present:

* `pass-with-missing` — a `PASS` summary over a `MISSING` required member, refused
  `OM_REFUSED_PASS_WITH_MISSING`;
* `reconciliation-mutated` — a signed reconciliation whose bytes changed after
  signing, refused `OM_REFUSED_RECONCILIATION_MUTATED`.

`OM_REFUSED_UNREADABLE_AS_ABSENT` has two controls, one per direction. The
positive control reaches `OM_VERIFIED` and establishes the decision procedure,
not a real closure.

## 7. Defects found

**Found in an existing record, recorded and not repaired.** The whole tools suite
is **1,403 tests with 1 failure**:

```
FAIL: test_two_runs_are_byte_identical_and_match_committed
(test_sigstore_bundle.DeterminismAndRecords)
AssertionError: ... "s": 413 ... != ... "s": 407 ... : committed differs: INVENTORY.json
```

A16's `evidence/a16/INVENTORY.json` committed `populationFiles: 407` over
`evidence/**/*.json`; A17's six tracked JSON records make the live population
413, so A16's own determinism check now produces a different inventory. This is
the same class of cross-item drift A13 recorded against A11's scan. Regenerating
A16's inventory (and its receipt) is an A16 record repair; it is outside this
item's write scope, which is limited to `evidence/a17/` (new files), the two
named documents and the two named tool files. The check was not relaxed and A16's
files were not edited.

**No defect in A15's records.** The re-run reproduced all five committed files
byte-for-byte; every `expectedDigest` matched.

**Development corrections, preserved.** (a) The first draft of `close` required a
caller-supplied digest whenever `exitCode` was 0, which would have refused a
legitimate close where the bytes exist; it was corrected before any record was
produced so that the exit-status rule fires only when the status is the sole
evidence (no bytes at the path). (b) The document-synchronisation control caught
a line break between "not a" and "safety" in the non-claim sentence; the
document was reflowed and the test normalises whitespace. Neither is a defect in
an existing record.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 22 19 0 4 23` (available 23 GiB); `Swap: 45 34 11` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}'` | `6442450944 6442450944` (6 GiB); available 23 GiB is below the 24 GiB build floor, so no build; the existing court was reused |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1403 tests in 223.929s`; `FAILED (failures=1)`; `closure discipline self-test: 7 control groups passed`. **1,360 pre-existing tests are present** (1,360 + 43 = 1,403), none ignored; the one failure is the A16 inventory drift in §7 |
| focused controls | `python3 -m unittest forensics.tools.tests.test_omission` | `Ran 43 tests in 0.295s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on the six records including the envelope | `json.tool ok FREEZE-a15.json`, `FREEZE-forward.json`, `RECONCILIATION-a15.json`, `RECONCILIATION-a15.envelope.json`, `STATUS.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a17/build_evidence.py --out /tmp/a17-run1` and `... /tmp/a17-run2` | `a17: a15 expected=5 produced=5 missing=0 unreadable=0 digestMismatch=0 unexpected=0 pass=true forward=20 forwardState=OPEN controls=17 codes=16 commit=731b066e2` twice |
| producer byte-identity | `cmp` of each name, run1 vs run2 vs committed | `identical run1=run2=committed FREEZE-a15`, `FREEZE-forward`, `RECONCILIATION-a15`, `RECONCILIATION-a15.envelope`, `STATUS`, `CONTROLS` |
| CLI, A15 cycle | `omission.py close FREEZE-a15.json ... --observe-dir <fresh A15 re-run>`; `omission.py verify FREEZE-a15.json RECONCILIATION-a15.json RECONCILIATION-a15.envelope.json` | `omission: code=OM_CLOSED expected=5 produced=5 missing=0 unreadable=0 digestMismatch=0 unexpected=0 pass=true`; `closed-a15-identical-to-committed`; `omission: code=OM_VERIFIED keyid=test-only:hmac-sha256:8e10a5a15d233d54 expected=5 produced=5 missing=0 unreadable=0 digestMismatch=0 unexpected=0 pass=true` |
| CLI, forward freeze | `omission.py close FREEZE-forward.json ...`; `omission.py sign ...`; `omission.py verify ...` | `omission: code=OM_CLOSED expected=20 produced=0 missing=20 unreadable=0 digestMismatch=0 unexpected=0 pass=false`; `omission: code=OM_OK payloadType=application/vnd.openssl-rs.a17.reconciliation+json keyid=test-only:hmac-sha256:8e10a5a15d233d54`; `omission: code=OM_VERIFIED keyid=test-only:hmac-sha256:8e10a5a15d233d54 expected=20 produced=0 missing=20 unreadable=0 digestMismatch=0 unexpected=0 pass=false`. This forward close and its envelope were written to `/tmp`, not committed: the forward freeze stays `OPEN` |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/OMISSION-RESISTANCE.md`, `?? evidence/a17/`, `?? forensics/tools/omission.py`, `?? forensics/tools/tests/test_omission.py` |

## 9. Obligations retained

* **No independent closer.** Every envelope is signed with A10's test-only
  HMAC-SHA256 key and is `SELF_ISSUED` under A12. The signature is a byte-integrity
  seal over a self-issued closure.
* **The times are declared.** `frozenAt` and `recordedAt` are literals chosen by
  the producer, not clock readings. `OM_REFUSED_FREEZE_AFTER_EXECUTION` can
  detect an inconsistent declared order; it cannot prove wall-clock order. A
  producer that misstates its own times is outside this mechanism.
* **The population is only as good as the freeze.** A freeze that omits an
  expected artefact, or declares the wrong predicate, yields a closure that is
  arithmetically correct and substantively incomplete. This mechanism detects
  omission relative to a declared population; it does not establish that the
  declared population is complete.
* **The forward population is a queue reading.** Its 20 members are derived from
  `docs/ETP-TODO.md` and `docs/ETP-ADDENDUM-B.md`. Whether future items will
  require additional records is a judgement no check here establishes.
* **An observed artefact is not authenticated.** `close` reads whichever bytes the
  observer points at; `UNEXPECTED` reporting does not prove origin.
* **A16's inventory drift is unrepaired.** Regenerating `evidence/a16/INVENTORY.json`
  is an A16 record repair, outside this item's write scope. The check is not
  relaxed.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## 10. `NOT_RUN`

* A real independent closer or external trust root: none exists.
* A wall-clock, RFC 3161 or transparency-log timestamp for `frozenAt` or the
  reconciliation: no timestamp authority and no log are configured.
* Inclusion of any freeze or reconciliation in a transparency log: B1-B5 are TODO.
* Closure of the forward freeze: it is `OPEN` by design and has no reconciliation.
* Completeness of the forward freeze's declared population.
* Any safety, compatibility, cryptographic or build result: this is evidence
  bookkeeping, not a measurement.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite (`src/` was
  not modified, so no rebuild and no `cargo test` is claimed).
