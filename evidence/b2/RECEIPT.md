# B2 receipt — an imprint can be checked offline; a trusted time cannot be invented

## 1. Identity of this batch

| field | value |
|---|---|
| item | B2 (`docs/ETP-ADDENDUM-B.md` §B.30; section F of `docs/ETP-TODO.md`), split **B2a / B2b** |
| status | **`PARTIAL`** — B2a `NOT_RUN`, B2b implemented and controlled with deterministic fixtures |
| branch | `staging` |
| HEAD at the start | `ebc539869` (`b1: a fixture can prove the verifier, not the service`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 33 8 0 4 11` (available **11** GiB); `Swap: 45 45 0` |
| `free -g` after the suite | `Mem: 45 35 6 0 4 10` (available **10** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944`), CPU quota **8 cores** (`8000000000`), repository at `/work`; **reused, not restarted** |
| interpreter in the court | CPython **3.11.2** |
| heavy commands | one at a time; no Rust build |

Available memory was **11 GiB**, below the 24 GiB floor `AGENTS.md` §6.1 sets
before a build, and it fell to 10 GiB after the suite. No build was needed or
attempted: every gate is Python. The derived cap `min(8g, available − 16g)` is
negative, so **no new court was started**; the existing 6 GiB court was reused
and every gate ran inside it. `docker/` was not modified. The run completed
without an OOM or a cgroup kill, and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/timestamp.py` | 2,085 | the offline verifier and the nine-times model: strict DER reader, CMS `ContentInfo`/`SignedData`, `TSTInfo` (version, policy, messageImprint, serialNumber, genTime, accuracy, nonce), imprint verification, EKU/signature/root-presence checks only with a caller-supplied certificate and function, 15 stable refusal codes plus `TS_OK`/`TS_NO_TOKEN`/`TS_REFUSED_USAGE`/`TS_REFUSED_IO`, nine slots and ordering invariants; CLI `times`, `verify`, `scan` |
| `forensics/tools/tests/test_timestamp.py` | 653 | 71 controls: strict-DER malformations, imprint both ways, algorithm/version/genTime/accuracy/nonce, EKU/signature/root/live-service, the nine slots and every ordering invariant, collapsed/unsourced/clock/inference cases, never-`TRUSTED`, the structural no-network test, determinism, CLI exit codes, document synchronisation |
| `docs/TRUSTED-TIMESTAMPING.md` | 361 | the normative document: the two claims, the nine times and their clauses, the ordering invariants, the verifier and its structure, what a trust root is needed for, the real result, the controls and canaries, the full refusal table, non-claims, `NOT_RUN` |
| `evidence/b2/build_evidence.py` | 848 | the deterministic producer for the four records; `--check` recomputes and compares bytes |
| `evidence/b2/TIMES.json` | produced | the nine slots for five real artefacts, with sources and `established` states, and the two-claims split |
| `evidence/b2/TOKENS.json` | produced | **zero** tokens found and `NO_TOKEN` for every artefact, with the reason |
| `evidence/b2/VERIFICATION.json` | produced | per artefact `NO_TOKEN` with every axis `NOT_RUN`; aggregate `trusted: 0` |
| `evidence/b2/CONTROLS.json` | produced | 16 control-only fixtures, one per refusal code, each with its canary and embedded deterministic token |
| `docs/ETP-TODO.md` | 1 row | the B2 row changed from `TODO` to `PARTIAL`; no other row touched |
| `evidence/b2/RECEIPT.md` | this file | the receipt |

The producer is the only writer of the four records. No file with a token suffix
was added: the fixtures live in `CONTROLS.json` as base64 and are labelled
`control-only`, so `TOKENS.json` at zero is a true observation, not a scan that
skipped its own fixtures.

## 3. The nine times of §B.9

The model has nine slots, each `{name, clause, kind, value, source, recordedBy,
accuracy, established}` plus a reason. The clause names are quoted from §B.9.
`TIMES.json` applies it to the four frozen A9 statements and the B1 fixture
publication: **5 artefacts × 9 slots = 45 slots; 10 `true`, 28 `unknown`, 7
`false`; 0 refusals.**

| # | slot | kind | A9 statement `a8-shard-000` | B1 publication |
|---:|---|---|---|---|
| 1 | `source-creation` | local | `unknown` — A8 names candidates, no date | `unknown` — same |
| 2 | `experimental-execution` | local | `unknown` — runs carry candidates, not times | `unknown` — same |
| 3 | `evidence-production` | local | `2026-11-24`, **day**, `a9/STATEMENTS.json#/sourceIdentity/asOf` | `2026-11-24`, **day**, `b1/PUBLICATION.json#/recordedAt` |
| 4 | `statement-authentication` | client | `2026-11-24`, **day**, `a10/ENVELOPES.json#/sourceIdentity/asOf` (test-only HMAC) | same A10 source |
| 5 | `trusted-timestamping` | authority | `unknown` — `TA-B2` `UNMET` | `unknown` — `TA-B2` `UNMET` |
| 6 | `transparency-inclusion` | log | `unknown` — no admitted log; `FIXTURE-1` has no integrated time | `false` — inclusion is in `FIXTURE-1`, not a log |
| 7 | `witness-observation` | verifier | `unknown` — no witness (`TA-B5` `UNMET`) | `false` — no witness observed a fixture |
| 8 | `release-promotion` | publication | `unknown` — no release promoted | `unknown` — no release promoted |
| 9 | `correction-or-revocation` | publication | `false` — no correction exists | `false` — no correction exists |

The other three A9 statements (`a1-sarif`, `a5-admission`, `a7-delta`) carry the
same pattern and their own digests. No slot holds an instant: the two
established slots hold a **date** because the producers record a date, and each
slot's `reason` says so. No slot is filled from the wall clock and no slot is
inferred from another.

Ordering invariants enforced: `source-creation` → `experimental-execution` →
`evidence-production` → `statement-authentication` → `trusted-timestamping` →
`transparency-inclusion`, then inclusion → `witness-observation` and inclusion →
`release-promotion` → `correction-or-revocation`. An unexplained inversion is
`TS_REFUSED_ORDER`; a shared value from the same source and recorder is
`TS_REFUSED_TIME_COLLAPSED`; a value without a tracked source, a bare clock read,
or execution inferred from a timestamp is `TS_REFUSED_TIME_UNSOURCED`.

## 4. The verifier result

| artefact | imprint | signature | chain | EKU | root | outcome |
|---|---|---|---|---|---|---|
| `a9-a1-sarif` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `a9-a5-admission` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `a9-a7-delta` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `a9-a8-shard-000` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `b1-publication` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |

Aggregate: `artefacts 5`, `noToken 5`, `imprintVerified 0`, `signatureVerified
0`, `chainVerified 0`, `rootAdmitted 0`, **`trusted 0`**. On the deterministic
control fixture the verifier reaches `code=TS_OK
outcome=TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED imprint=PASS signature=PASS
chain=NOT_RUN eku=PASS root=NOT_RUN nonce=RECORDED
accuracy=seconds=0,millis=1,micros=1`, `trusted=false`. That is the verifier
working on a fixture; it is not a result for any artefact.

`TIMESTAMP_TRUSTED` exists as a named outcome and is never produced. The code
asserts it after the root-presence branch, and the tests assert it for every
control.

## 5. Controls

`CONTROLS.json` records **16 control-only fixtures: 16/16 fired, 16/16 canaries
accepted, `onePerCode: true`**. Every fixture is deterministic (fixed control
seed, `genTime` `20261124000000Z`, serial 1, nonce 7, fixture-local policy OIDs)
and embedded as base64 with its SHA-256.

| # | control | refusal code | canary |
|---:|---|---|---|
| 1 | truncated token | `TS_REFUSED_DER` | unmutated token accepted |
| 2 | one trailing byte | `TS_REFUSED_DER` | unmutated token accepted |
| 3 | `TSTInfo.version` = 2 | `TS_REFUSED_VERSION` | version 1 accepted |
| 4 | imprint of another artefact | `TS_REFUSED_IMPRINT` | declared artefact's imprint accepted |
| 5 | SHA-384 token, SHA-256 declared | `TS_REFUSED_ALGORITHM` | SHA-256 token accepted |
| 6 | `genTime` absent | `TS_REFUSED_GEN_TIME` | token with `genTime` accepted |
| 7 | certificate without EKU | `TS_REFUSED_EKU` | EKU certificate accepted |
| 8 | corrupted signature | `TS_REFUSED_SIGNATURE` | correctly signed fixture accepted |
| 9 | required root absent | `TS_REFUSED_ROOT` | same token accepted without `require_root` |
| 10 | live-service assertion | `TS_REFUSED_LIVE_SERVICE` | normal policy accepted |
| 11 | expected nonce 8, token 7 | `TS_REFUSED_NONCE` | expected nonce 7 accepted |
| 12 | accuracy millis 1000 | `TS_REFUSED_ACCURACY` | millis 1 accepted |
| 13 | nine slots, one value | `TS_REFUSED_TIME_COLLAPSED` | nine distinct times accepted |
| 14 | slot value without source | `TS_REFUSED_TIME_UNSOURCED` | sourced fixture accepted |
| 15 | authentication before production | `TS_REFUSED_ORDER` | correctly ordered fixture accepted |
| 16 | eight slots | `TS_REFUSED_TIME_MODEL` | nine-slot fixture accepted |

The positive control is the valid token + valid nine-slot record: `TS_OK`,
`TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED`, `trusted: false`. A control that fires
proves the verifier rejects that mutation; it does not prove any TSA behaves as
the fixture does, and a fixture token is not an authority.

## 6. Defects found

**Existing records: none contradicted.** The producer re-read
`evidence/a9/STATEMENTS.json`, `evidence/a10/ENVELOPES.json`,
`evidence/b1/PUBLICATION.json`, `evidence/a8/MANIFEST.json`,
`evidence/b0/SERVICE-CONFIGURATION.json` and `evidence/b0/REGISTRY.json`.
`TA-B2` is `UNMET`, the presence facts are as B0 recorded them, and the fixture
publication's `inclusion` is exactly the fixture inclusion B1 described. No
existing record was edited and no check was relaxed.

**Development defects in this item's own machinery**, preserved because a control
that passes for the wrong reason is the defect this item exists to catch:

1. The accuracy fields `millis [0]` and `micros [1]` are implicitly tagged
   INTEGERs. The first parser sent them through the universal INTEGER tag check,
   so the valid fixture was refused `TS_REFUSED_DER` at
   `TSTInfo.accuracy.millis`. The tag check and the content-minimality check were
   separated (`_integer_content`); the strictness was not reduced — the content
   is still minimal and in range.
2. The fixture builder's variant whitelist rejected `malformed-der` and
   `trailing-byte`, so those two controls could not be generated. The whitelist
   was widened for exactly those variants; no verifier check changed.
3. `onePerCode` was `False` on the first producer run because
   `TS_REFUSED_TIME_MODEL` had no control. An eight-slot control was added; the
   code was not dropped from the vocabulary to make the summary green.
4. A test referenced `timestamp._sha256_bytes`, a helper that did not exist. The
   test was corrected to use `hashlib` directly rather than adding a helper that
   the module does not need.
5. The document-synchronisation test compared non-claim phrases case-sensitively
   while the document capitalised sentence starts, and the `NOT_RUN` heading was
   numbered. The document follows the B1 convention (`## `NOT_RUN``) and the test
   compares case-folded text; the test still requires every non-claim.
6. The test that parses every embedded fixture assumed only the DER controls
   refuse at parse time. Version, absent-`genTime` and accuracy refusals all occur
   in `parse_tstinfo`. The test now asserts the refusal is one of the structural
   set — a stronger assertion than skipping the fixture.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container (CPython 3.11.2), one
at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before: `Mem: 45 33 8 0 4 11` (available **11** GiB), `Swap: 45 45 0`; after: `Mem: 45 35 6 0 4 10` (available **10** GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect` | `Mem=6442450944 MemSwap=6442450944 NanoCpus=8000000000`; reused, not restarted; no new court because the §6.1 floor was not met |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2138 tests in 451.691s`; `OK`; `closure discipline self-test: 7 control groups passed`. The **2,067 pre-existing tests are present** (2,067 + 71 new = 2,138), none removed, none ignored, no skips reported |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on the four records | `TIMES.json JSON_OK`; `TOKENS.json JSON_OK`; `VERIFICATION.json JSON_OK`; `CONTROLS.json JSON_OK` |
| 5. producer, twice | `python3 evidence/b2/build_evidence.py` twice | each: `b2: artefacts=5 slots=45 established=10 unknown=28 notEstablished=7 refusals=0`; `b2: tokensFound=0 noToken=5 trusted=0`; `b2: controls=16 fired=16 canariesAccepted=16 onePerCode=True`; `b2: codes=NONE`. `sha256sum` before, after run 1 and after run 2: both `diff`s clean, **BYTE-IDENTICAL**. `--check`: `b2: check ok records=4 controlOnly=true trusted=0`; `CHECK_EXIT=0` |
| 6. CLI times | `timestamp.py times` | `code=TS_OK artefacts=5 slots=9`; 45 `slot=` lines; `TIMES_EXIT=0` |
| 6. CLI verify, no token | `timestamp.py verify --artifact evidence/a9/STATEMENTS/a8-shard-000.json` | `code=TS_NO_TOKEN outcome=TIMESTAMP_NO_TOKEN no token was supplied`; `NOTOKEN_EXIT=0` |
| 6. CLI verify, fixture | `timestamp.py verify … --control-fixture valid` | `code=TS_OK outcome=TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED imprint=PASS signature=PASS chain=NOT_RUN eku=PASS root=NOT_RUN nonce=RECORDED accuracy=seconds=0,millis=1,micros=1`; `algorithm=sha256 genTime=20261124000000Z policy=1.2.3.4.5.6.7.8.1 serial=1 tokenCertificates=1 trusted=false`; `VALID_EXIT=0` |
| 6. CLI verify, refusal | `timestamp.py verify … --control-fixture wrong-imprint` | `code=TS_REFUSED_IMPRINT outcome=TIMESTAMP_REFUSED … trusted=false`; `WRONG_EXIT=1` |
| 6. codes that fire | `CONTROLS.json#/summary/refusalCodes` | `TS_REFUSED_ACCURACY`, `TS_REFUSED_ALGORITHM`, `TS_REFUSED_DER`, `TS_REFUSED_EKU`, `TS_REFUSED_GEN_TIME`, `TS_REFUSED_IMPRINT`, `TS_REFUSED_LIVE_SERVICE`, `TS_REFUSED_NONCE`, `TS_REFUSED_ORDER`, `TS_REFUSED_ROOT`, `TS_REFUSED_SIGNATURE`, `TS_REFUSED_TIME_COLLAPSED`, `TS_REFUSED_TIME_MODEL`, `TS_REFUSED_TIME_UNSOURCED`, `TS_REFUSED_VERSION` |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/TRUSTED-TIMESTAMPING.md`; `?? evidence/b2/`; `?? forensics/tools/tests/test_timestamp.py`; `?? forensics/tools/timestamp.py` — nothing else |

The full discovery ran after the final code and document fixes (implicit accuracy
tags, the DER variants, the time-model control, the test corrections and the
document wording). Only this receipt and the queue row were written afterwards;
they change no code and no test.

## 8. Obligations retained

* **An imprint match is not a trusted time.** The hash comparison is real and
  offline; it says nothing about who asserted when.
* **A fixture token is not an authority.** Its signature is HMAC-SHA256 under a
  fixed public seed, its certificate carries no CA signature, and no TSA issued
  it. `SELF_ISSUED` is not a pass.
* **A caller-supplied root is presence-only.** `root=PRESENCE_ONLY` records that
  the DNs line up; it is not an admission and the outcome stays `UNTRUSTED`.
* **No clock is trustworthy because it is read.** No slot is filled from the wall
  clock; a clock source is refused as unsourced.
* **Nine slots do not prove nine events.** They prove the record does not
  conflate the events it claims.
* **A recorded date is not an instant.** The two established slots are at day
  accuracy and say so; no slot invents a time of day.
* **The controls are not conformance.** A refusal proves the verifier rejects
  that mutation, not that any external TSA behaves as the fixture does.
* **The forward freeze remains `OPEN`.** Producing `b2-receipt` satisfies its
  predicate; it does not close the freeze.

## 9. `NOT_RUN`

* B2a in full: any RFC 3161 request, token, TSA, certificate, chain, EKU
  evaluation, root admission, policy admission, nonce correspondence,
  revocation or historical-validity check for a real token.
* Any network access, and any invocation of `openssl`, `tsget` or `curl`.
* Any real transparency inclusion time, witness observation, release promotion or
  correction/revocation event.
* Independent review, BOUNDARY and SEAL evidence, and the Rust suite (`src/` was
  not modified).

## 10. The forward-freeze member

`evidence/a17/FREEZE-forward.json` declares one B2 member:

* `b2-receipt` — `path: evidence/b2/RECEIPT.md`, predicate "a receipt records the
  RFC 3161 timestamp evidence and offline verification".

This file exists at that path and records the RFC 3161 result (zero tokens, every
artefact `NO_TOKEN`, aggregate `trusted: 0`) and the offline verification
(verifier, controls, nine times, `NOT_RUN`). The detailed records are under
`evidence/b2/` and are named here. The member predicate is satisfied; the freeze
itself remains `OPEN` and is closed only at A17's own record.
