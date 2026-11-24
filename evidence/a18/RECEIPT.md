# A18 receipt — survivable key compromise on TUF principles

## 1. Identity of this batch

| field | value |
|---|---|
| item | A18 (survivable key compromise: rotation, delegation, expiry, revocation, anti-rollback, anti-freeze) |
| branch | `staging` |
| HEAD at the start | `2e8e9aa65ba60321c18f54890aa73caa200f5bd7` (`a16: bind the bundle inventory to a declared candidate`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 22 18 0 5 23` (total 45, used 22, free 18, available **23** GiB); `Swap: 45 36 9` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool or evidence modified |

The machine had 23 GiB available, below the 24 GiB floor §6.1 sets before a
build. No build was needed or run: every gate is Python-only. The derived cap
would have been `min(8, 23 - 16) = 7 GiB`, above the 2 GiB floor, and the
already-running 6 GiB court was reused rather than starting a second court, as
A7-A17 did. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/key_lifecycle.py` | 1,346 lines | the model, the 21 refusal codes, the evaluator and the CLI |
| `forensics/tools/tests/test_key_lifecycle.py` | 559 lines | 49 controls: coverage, each rollback role, rotation sides, revoked verifying signature, freeze boundary, hash chain, stale release, `NOT_RUN`, determinism, CLI, document synchronisation |
| `docs/KEY-LIFECYCLE.md` | 323 lines | the normative document, including all 21 codes and the non-claims |
| `evidence/a18/build_evidence.py` | 676 lines | deterministic producer of the three records |
| `evidence/a18/INVENTORY.json` | record | the real one-key inventory and the single-point finding |
| `evidence/a18/EVALUATION.json` | record | every role `NOT_RUN`; the stale-release check `NOT_RUN` |
| `evidence/a18/CONTROLS.json` | record | 22 `control-only` controls over the 21 codes, plus a positive |
| `docs/ETP-TODO.md` | 1 row | the A18 row replaced from `TODO` to `DONE`; no other row touched |
| `evidence/a18/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `INVENTORY.json` | `249eaadb5de8c1363a77d58b3c19bd741f70af2c67c513bdd1b2cb172faa7c8f` |
| `EVALUATION.json` | `70602b4ae54e0deec1cba3732f1855f788be7ef4b8981d3f5a368d3e0c7d3939` |
| `CONTROLS.json` | `565b20b846121150f6d62b4412a00027701e0327f1147d0b82d079fa4dde6702` |

## 3. The rule

> An old signature never authorises a stale release.

A signature says that whoever holds a key approved some bytes. It does not make
the approval survivable. The mechanism adds the properties that make a
compromise detectable and recoverable: a second root to rotate to, a metadata
version to compare, an expiry to stop old metadata, a revocation record to
withdraw a key, a hash chain to bind role names to bytes, and a refresh interval
to stop a valid-looking repository being frozen forever.

## 4. The model and the evaluation order

A repository is `{metadata: {root, targets, snapshot, timestamp}, delegations,
releases, maxTimestampInterval}`. Every metadata record carries `role`,
`version`, `expires`, `threshold`, `keys` and `signatures`, plus the role's chain
reference. `snapshot` names the `targets` version and digest; `timestamp` names
the `snapshot` version and digest and carries `issuedAt`; `targets` declares each
delegation by name and digest. The root anchors the non-root role keys; a
delegation record's own keys are authoritative because the parent binds the whole
record by digest.

Signatures are a **structural test-only digest model**:
`"sha256:" + SHA-256(canonical signed body || 0x00 || keyid)`. It catches a
signature that was not produced over the bytes under test and lets a control
show a revoked key whose signature verifies. It has no secret and establishes no
authenticity; real verification is `NOT_RUN`.

`evaluate(repository, now, previous)` applies the rules in order: repository
shape; root version/expiry/signatures and both thresholds; targets; snapshot;
timestamp; delegations; releases; then the hash chain and the freeze check. It
refuses with the first code that fires. `previous` is the last accepted metadata
set, or `None` for an initial root. No clock is read.

The anti-freeze boundary is declared: freeze iff
`now - issuedAt > maxTimestampInterval`. Exactly the interval is accepted; one
second past is `TK_REFUSED_FREEZE`.

## 5. The real inventory and evaluation

`INVENTORY.json` records the measured state:

* **one key**, `test-only:hmac-sha256:8e10a5a15d233d54`, `symmetric: true`,
  derived from a fixed public seed; **no expiry**, **no revocation record**,
  **no metadata version**, **no delegation**;
* **0 repositories**, 0 metadata versions, 0 revocation records, 0 expiry
  records, 0 delegations.

The finding is explicit and is the honest result, not an omission: the one key
is a **single point of compromise** with no detectable recovery. There is no
second root to rotate to, no revocation list to consult and no metadata version
to distinguish a signature made before a hypothetical compromise from one made
after it. **A bundle or envelope signed before the compromise is
indistinguishable from one signed after it.**

`EVALUATION.json` records every role (`root`, `targets`, `snapshot`, `timestamp`,
`delegation`) and the stale-release check as `NOT_RUN` with `TK_NOT_RUN`. **0
repositories and nothing accepted.** A repository that does not exist is never
`ACCEPTED`.

**Every code that fires on real data:** only `TK_NOT_RUN`. None of the 21
refusal codes fires, because there is no repository to evaluate. That is a
negative result, not a pass, and the refusal table is exercised only by the
controls.

## 6. The controls

`CONTROLS.json` holds **22** `control-only` synthetic repositories over the **21**
stable codes, plus one positive control. Each control is built in memory by the
producer and the producer refuses to emit a record whose observed code differs
from the declared one.

The required controls are present and named: `rotation-unsigned-by-old` (root
rotation signed only by the new root), `targets-rollback`, `snapshot-hash-mismatch`,
`expired-metadata`, `freeze`, `key-revoked-verifying-signature`,
`delegation-expired` and `stale-release-version`; a second stale-release
direction (`stale-release-revoked-key`) covers a key revoked at or before the
release's recorded time. `positive-accepted` is a version-incremented root
rotation signed by both the old and the new root keys, threshold-two signed,
with a hash-bound unexpired delegation and unexpired metadata; it reaches
`ACCEPTED`.

What the positive establishes: the decision procedure can accept a consistent,
monotonic, threshold-signed, hash-bound repository, so the refusals are not
vacuous. What it does not establish: that any such repository exists, that its
keys are honestly held, that a ceremony happened, or that an accepted release is
safe or authentic. It is a control, not a repository.

## 7. Defects found

**No defect in an existing record was found by any gate.** Every gate ran
clean on the first attempt; no existing record was rejected, repaired or
relaxed. A16's inventory is frozen at its declared candidate and reports the
three new A18 JSON records as `NEW_SINCE_RECORD` rather than absorbing them, so
the cross-item inventory drift A17 recorded did not recur.

**Development corrections, before any record was produced.** (a) The `future`
control key was first given `notBefore` 2027-06-01 and `notAfter` 2027-01-01,
which the structural validator correctly refused as an inverted window; the
control now uses 2028-01-01. (b) The document-synchronisation control found that
an "Enforced by" line wrapped before its control name, and another carried a
control name but no code or test; the lines were reflowed so each names a code
or a test. Neither is a defect in an existing record.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 22 18 0 5 23` (available 23 GiB); `Swap: 45 36 9` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}'` | `6442450944 6442450944` (6 GiB); reused, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1464 tests in 235.457s`; `OK`; `closure discipline self-test: 7 control groups passed`. **1,415 pre-existing tests are present** (1,415 + 49 = 1,464), none ignored, none removed |
| focused controls | `python3 -m unittest forensics.tools.tests.test_key_lifecycle` | `Ran 49 tests in 0.257s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 (re-run after the `docs/ETP-TODO.md` row was replaced) |
| JSON well-formedness | `python3 -m json.tool` on the three records | `json.tool ok INVENTORY.json`, `EVALUATION.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a18/build_evidence.py --out ...` twice | `a18: keys=1 repositories=0 outcome=NOT_RUN code=TK_NOT_RUN controls=22 codes=21 positive=ACCEPTED base=2e8e9aa65` twice |
| producer byte-identity | `cmp` of each name, run1 vs run2 vs committed | `identical run1=run2=committed INVENTORY`, `EVALUATION`, `CONTROLS` |
| CLI, real evaluate | `python3 forensics/tools/key_lifecycle.py evaluate evidence/a18/REPOSITORY.json --now 2026-11-24T00:00:00Z` | `outcome=NOT_RUN code=TK_NOT_RUN`, every role and the stale-release check `NOT_RUN`, exit 1 |
| CLI, real inventory | `python3 forensics/tools/key_lifecycle.py inventory` | `inventory: code=TK_OK outcome=NOT_RUN keys=1 repositories=0 metadataVersions=0 revocationRecords=0 expiryRecords=0 delegations=0 singlePointOfCompromise=True`, exit 0 |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/KEY-LIFECYCLE.md`; `?? evidence/a18/`; `?? forensics/tools/key_lifecycle.py`; `?? forensics/tools/tests/test_key_lifecycle.py` |

## 9. Obligations retained

* **No real repository exists.** Every rule is exercised only against synthetic
  `control-only` repositories. Nothing about a real metadata set, key or release
  was measured.
* **The signature model is not cryptography.** It is a deterministic digest with
  no secret; it demonstrates the decision procedure and nothing about
  authenticity.
* **The refresh interval is declared by the repository itself.** A malicious or
  mistaken repository can declare a very large `maxTimestampInterval`; the tool
  refuses a freeze past the declared interval, not past a policy interval. The
  interval is a policy input, not a measured fact.
* **Rotation protects only while the old root is uncompromised.** If the old
  root key is the stolen key, the attacker can perform a correctly co-signed
  rotation. Detecting that requires an out-of-band root pin, which does not
  exist here.
* **The root anchors role keys; a compromised root can re-key everything.** That
  is inherent in a root-of-trust model and is not repaired by rotation.
* **Delegation keys are anchored by the parent digest, not by the root.** A
  compromised but validly signed `targets` can delegate; the parent digest binds
  the delegation to the targets that approved it, not to an independent root.
* **Release records are unsigned in this model.** The stale-release rule binds a
  release's version, time and keyid; it does not verify a release signature or
  a release artefact.
* **The times are declared.** `now` is supplied; the producer uses a literal.
  A producer that misstates its own time is outside this mechanism.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.
* **The forward freeze is open.** This item satisfies its one declared member;
  the freeze itself is not closed and is not evidence that the other items are
  done.

## 10. `NOT_RUN`

* Any real repository, root, targets, snapshot or timestamp metadata set: 0
  repositories exist.
* A real root rotation, delegation, expiry record or revocation record: none
  exists.
* Any real accepted release and any stale-release decision on real data.
* Real signature verification, a production key, a key ceremony, key
  distribution and revocation propagation.
* A second root or any external trust root: the only key is A10's test-only
  symmetric key.
* A wall-clock, RFC 3161 or transparency-log timestamp for any evaluation.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite (`src/` was
  not modified, so no rebuild and no `cargo test` is claimed).

## 11. Forward-freeze members

`evidence/a17/FREEZE-forward.json` declares **one** A18 member:

* **satisfied:** `a18-receipt` — `evidence/a18/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

Still open under the same freeze (19 members, not this item's work):
`a19-receipt` … `a27-receipt` (9 remaining, A19-A27), `b0-registry`,
`b0-service-configuration`, and `b1-receipt` … `b8-receipt` (8). The freeze
remains `state: OPEN`; it was not amended and not closed, and this receipt does
not claim any of those members.
