# A15 receipt — thresholds over distinct trust domains

## 1. Identity of this batch

| field | value |
|---|---|
| item | A15 (thresholds over distinct authorised keys and distinct trust domains; repeated signatures and aliases cannot satisfy independence) |
| branch | `staging` |
| HEAD at the start | `b099cd599` (`a14: a signature is not an authorisation`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 21 20 0 4 24` (total 45, used 21, free 20, available **24** GiB); `Swap: 45 33 12` |
| derived court cap | `min(8g, 24 - 16) = 8g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The derived cap is 8 GiB and the running container's cap is 6 GiB, which is below
it. The container was reused rather than restarted, as A7–A14 did. Every reported
gate is Python-only and ran in that court with `PYTHONDONTWRITEBYTECODE=1` so the
bind-mounted tree gained no `__pycache__` entries. A14's four venue symlinks
(`/usr/local/bin/{binsec,rustc,cargo,rustup}`) were already present inside the
disposable container and no new venue repair was needed. No test was edited,
skipped, ignored or removed.

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/TRUST-THRESHOLDS.md` | 436 lines | normative document: the problem, the domain contract, the declaration and no-lowering rule, the evaluation order, the alias rule and count, the 13-code refusal table, the real result, the controls, the release-gate integration, the boundary with A12/A14/A16/A17, non-claims, obligations, `NOT_RUN`, reproduction |
| `forensics/tools/thresholds.py` | 1,204 lines | the domain contract, `distinct_domains`, `evaluate`, the 13 codes, the CLI (`domains`, `count`, `evaluate`) |
| `forensics/tools/tests/test_thresholds.py` | 687 lines | 54 controls: one per code, the five substitutions, both no-lowering triggers, reachability, both staleness triggers, the real records, the positive and alias controls, determinism, CLI, document synchronisation |
| `forensics/tools/release_gate.py` | 1,451 lines | the minimal integration: item 8, `check_thresholds`, constants, CLI options, docstring, pass line, four self-test controls |
| `forensics/tools/tests/test_release_gate.py` | 376 lines | 4 new controls for the threshold row (unmet, met, missing record, unparseable) |
| `evidence/a15/DOMAINS.json` | 56 lines | the real domain inventory: one same-party domain, `externalDomains: []` |
| `evidence/a15/THRESHOLDS.json` | 152 lines | the four declared thresholds and their digests |
| `evidence/a15/APPROVALS.json` | 43 lines | the real approvals: none |
| `evidence/a15/EVALUATION.json` | 202 lines | each threshold evaluated against the real approvals; aggregate 0 met |
| `evidence/a15/CONTROLS.json` | 2,546 lines | 15 refusal controls, the positive control, the alias control; every fixture `control-only` |
| `evidence/a15/build_evidence.py` | 751 lines | deterministic producer of the five records; asserts every control and the real aggregate 0 |
| `docs/ETP-TODO.md` | 339 lines | the A15 row replaced only; no other row touched |
| `evidence/a15/RECEIPT.md` | this file | the receipt |

## 3. The rule

> A k-of-n threshold counts **distinct established trust domains**, not labels.
> A domain label asserted by the approval is not a domain; two labels that
> resolve to one establishment are one domain; one domain approving twice is one
> domain; one identity under two labels contributes one domain; and the
> candidate's or a same-party domain is never an independent approval. A
> declaration made after the approvals were collected, or amended afterwards, is
> not the threshold that was met, and a threshold of k is unreachable when fewer
> than k distinct domains exist at all.

The evaluation order is: declaration known → no lowering → reachability → per
approval (domain resolves → established → not candidate/same-party → verified →
dates → role → digest/expiry) → identity collapse → domain collapse → count
against k. The role, identity and scope check is delegated to A14's assignment
records by calling `authorisation.authorise`; the seven roles and the separation
policy are not restated.

## 4. The real domains

`evidence/a15/DOMAINS.json` records one domain.

| domain | kind | established by | independent of candidate |
|---|---|---|---|
| `openssl-rs:same-party` | `same-party` | `evidence/a12/TRUST-ROOTS.json` (A12's single root, the A10 test-only HMAC-SHA256 key) | **false** |

`externalDomains` is `[]`. A12's inventory records one root, `symmetric: true`,
`trustDomain: "same-party"`, provenance inside the candidate. The record
establishes that the domain exists; it does not establish a domain independent of
the candidate. There are **0 external trust domains**. This is the measured
state, not an omission.

## 5. The real thresholds and evaluations

`evidence/a15/THRESHOLDS.json` declares four thresholds. `n` is the quorum the
policy contemplates; `domainsAvailable` is measured from the inventory and is 0.

| threshold | k | n | available domains | distinct domains | outcome | codes |
|---|---:|---:|---:|---:|---|---|
| `release` | 2 | 3 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |
| `claim-promotion` | 1 | 2 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |
| `consumer-graduation` | 2 | 3 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |
| `instrument-qualification` | 1 | 2 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |

`evidence/a15/APPROVALS.json` records no approval. No real signature exists
(A14 records every attempt `verified:false`; A10/A12 record only a test-only
symmetric key), and no external domain exists.

**Aggregate: 0 met, 0 unmet, 4 unreachable, 0 not run; 0 thresholds can be met.**
This is the honest result. It is not worked around by promoting the same-party
domain, counting a label twice, inventing an approval, or lowering k until the
empty approval set meets it.

## 6. The controls

`evidence/a15/CONTROLS.json` holds 15 refusal controls and one positive control,
all built from domains and identities labelled `control-only`.

| control | code | result |
|---|---|---|
| `threshold-unrecorded` | `TH_REFUSED_THRESHOLD_UNRECORDED` | fires; outcome `NOT_RUN` |
| `threshold-lowered-declared-late` | `TH_REFUSED_THRESHOLD_LOWERED` | fires |
| `threshold-lowered-amended` | `TH_REFUSED_THRESHOLD_LOWERED` | fires; amendment at the earliest approval |
| `threshold-unreachable` | `TH_REFUSED_THRESHOLD_UNREACHABLE` | fires; 0 external domains, k=2 |
| `self-asserted-domain` | `TH_REFUSED_SELF_ASSERTED_DOMAIN` | fires; count stays 1 |
| `domain-unrecorded` | `TH_REFUSED_DOMAIN_UNRECORDED` | fires; count stays 1 |
| `candidate-domain` | `TH_REFUSED_CANDIDATE_DOMAIN` | fires; count stays 1 |
| `alias-one-domain` | `TH_REFUSED_ALIASED` | fires; two labels, one establishment, **count 1** |
| `domain-duplicate` | `TH_REFUSED_DOMAIN_DUPLICATE` | fires; count stays 1 |
| `unverified` | `TH_REFUSED_UNVERIFIED` | fires; count stays 1 |
| `wrong-role` | `TH_REFUSED_WRONG_ROLE` | fires via A14's `RA_REFUSED_ROLE_NOT_ASSIGNED`; count stays 1 |
| `stale-digest` | `TH_REFUSED_STALE_APPROVAL` | fires; the artefact digest changed |
| `stale-expired` | `TH_REFUSED_STALE_APPROVAL` | fires; the approval expired |
| `insufficient-domains` | `TH_REFUSED_INSUFFICIENT_DOMAINS` | fires; reachable, only one domain qualifies |
| `duplicate-identity` | `TH_REFUSED_DUPLICATE_IDENTITY` | fires; one identity under two labels, count stays 1 |
| `positive-distinct-domains` | — | two distinct synthetic external domains reach `MET`, count 2; **control-only** |

The positive control establishes the counting procedure, not a real approval, a
real domain, a real authorisation or a real release. The alias control
establishes that two labels resolving to one establishment yield a count of one.
The producer asserts every control fires, the positive reaches `MET`, the alias
count is 1, and the real aggregate is 0; a control that stops firing fails the
build.

## 7. Release-gate integration

The gate has a per-refusal row structure: each checker returns
`Results(refusals, recorded)` and the gate combines rows without changing another
checker's verdict. A15 joins that seam as item 8, `check_thresholds`, without
changing items 1–7.

`check_thresholds` runs `forensics/tools/thresholds.py evaluate release --json`
against `evidence/a15/THRESHOLDS.json`, `evidence/a15/APPROVALS.json`,
`evidence/a15/DOMAINS.json` and `evidence/a14/ROLES.json`. A threshold that is
not `MET` is one row, `RG_THRESHOLD_UNMET`; an absent tool or record is
`RG_THRESHOLD_TOOL_MISSING`, `RG_THRESHOLD_MISSING` or
`RG_THRESHOLD_ROLES_MISSING`; an unparseable result is `RG_THRESHOLD_ERROR`. A
missing threshold check is never a skip.

**Before** (base tree, no A15 record; `--instrument-mode validate`):

```
release-gate: candidate b099cd599b6728a7b7686a76b515ff0b67a7acc1; clean worktree (ignored paths excluded)
REFUSED RG_AUTHORISATION_REFUSED a14/release: outcome=REFUSED codes=RA_REFUSED_SIGNATURE_UNVERIFIED,RA_REFUSED_INSUFFICIENT_SIGNERS; face-value codes=RA_REFUSED_SEPARATION,RA_REFUSED_INSUFFICIENT_SIGNERS
release-gate: REFUSED (32 item(s))
```

**After** (with the A15 record and the new item):

```
release-gate: candidate b099cd599b6728a7b7686a76b515ff0b67a7acc1; 6 uncommitted path(s) (tracked or untracked; ignored paths excluded)
REFUSED RG_AUTHORISATION_REFUSED a14/release: outcome=REFUSED codes=RA_REFUSED_SIGNATURE_UNVERIFIED,RA_REFUSED_INSUFFICIENT_SIGNERS; face-value codes=RA_REFUSED_SEPARATION,RA_REFUSED_INSUFFICIENT_SIGNERS
REFUSED RG_THRESHOLD_UNMET a15/release: outcome=UNREACHABLE codes=TH_REFUSED_THRESHOLD_UNREACHABLE distinctDomains=0 availableDomains=0
release-gate: REFUSED (33 item(s))
```

The 32 existing refusals are unchanged; the A15 row is the 33rd. The
constitution mapping in `docs/RELEASE_GATES.md` §10 is **not** updated and is
retained as an obligation: the table still names Articles 5, 6, 7 and 9 as
uncovered and does not list the new row. The integration itself is done; the
mapping decision is not.

## 8. Defects found

**No gate rejected an existing record.** The full tools suite was green at the
base and is green after the change (`Ran 1321 tests`, `OK`);
`docs_consistency.py` and `spec_guard.py check` are clean; all five JSON records
pass `python3 -m json.tool`. No contradiction was found across A12's root
inventory, A14's role record and this item: A12 records 0 external roots, A14
records 0 external trust domains, and A15 records 0 external domains. The
same-party domain is recorded with `independentOfCandidate: false` rather than
repaired into an external one.

One defect was found in this item's own new code and is preserved with its old
and new form. It failed before a control was reported as green.

| file | old form | new form | found by |
|---|---|---|---|
| `evidence/a15/build_evidence.py` | the `wrong-role` control signed `control-only-release` as `adjudicator`; the duplicate-identity control had already assigned that identity the `adjudicator` role, so the role check passed and `TH_REFUSED_WRONG_ROLE` never fired | the control signs `control-only-producer` as `release_authority`, a role that identity does not hold | the producer's own assertion: `control wrong-role failed: TH_REFUSED_WRONG_ROLE not in []` |

The defect was in the control, not the tool: it proved the control was not
isolating the code it claimed to exercise. The corrected control is refused at
A14's `RA_REFUSED_ROLE_NOT_ASSIGNED`, which the threshold maps to
`TH_REFUSED_WRONG_ROLE`.

## 9. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 21 20 0 4 24` (available 24 GiB); `Swap: 45 33 12` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1321 tests in 220.020s`; `OK`; `closure discipline self-test: 7 control groups passed`. **1,263 pre-existing tests are present** (1,263 + 58 = 1,321), **none ignored** |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `DOMAINS.json`, `THRESHOLDS.json`, `APPROVALS.json`, `EVALUATION.json`, `CONTROLS.json` | `ok` for all five, exit 0 each |
| producer, two runs | `python3 evidence/a15/build_evidence.py --out /tmp/a15a --source-commit b099cd599b6728a7b7686a76b515ff0b67a7acc1` and the same to `/tmp/a15b` | `a15: domains=1 external=0 thresholds=4 met=0 unreachable=4 approvals=0 controls=15 commit=b099cd599` twice |
| producer byte-identity | `cmp` of `/tmp/a15a/<name>`, `/tmp/a15b/<name>` and `evidence/a15/<name>` | `identical` and `committed-identical` for all five |
| the four real thresholds | `python3 forensics/tools/thresholds.py evaluate <threshold>` | exit 1 for all four; each `outcome=UNREACHABLE codes=TH_REFUSED_THRESHOLD_UNREACHABLE`; aggregate **0 met** |
| the domain inventory | `python3 forensics/tools/thresholds.py domains` | `recorded=1 external=0 candidateDomain=openssl-rs code=TH_OK outcome=NOT_RUN`, exit 0 |
| release gate before | `python3 forensics/tools/release_gate.py --instrument-mode validate` | `release-gate: REFUSED (32 item(s))`, exit 1, on a clean worktree |
| release gate after | the same command with the A15 record | `REFUSED RG_THRESHOLD_UNMET a15/release: ...`; `release-gate: REFUSED (33 item(s))`, exit 1; the 32 existing refusals unchanged |
| gate self-test | `python3 forensics/tools/release_gate.py --self-test` | `release-gate self-test: ok (25 cases)`, including the four threshold controls |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `M forensics/tools/release_gate.py`, `M forensics/tools/tests/test_release_gate.py`, `?? docs/TRUST-THRESHOLDS.md`, `?? evidence/a15/`, `?? forensics/tools/tests/test_thresholds.py`, `?? forensics/tools/thresholds.py` |

**Reproducibility.** The producer reads the bytes of A12's trust-root inventory,
A14's role record and the four subject records; every digest is computed from
bytes. Two runs are byte-identical and the committed files match a fresh build,
enforced by `test_builder_is_byte_identical_twice_and_matches_committed` and
`test_build_is_deterministic_in_process`. The source identity is supplied
(`--source-commit`); without it the recorded `BASE_COMMIT` is reused, never a
live `HEAD`.

## 10. Obligations retained

* **`docs/RELEASE_GATES.md` §10 is not updated.** The gate runs the new row, but
  the constitution's gate-item table does not list it and still names Articles 5,
  6, 7 and 9 as uncovered. Deciding which article the threshold row evidences,
  and updating the table, is a separate change.
* **No external trust domain exists.** No record establishes a domain outside
  the candidate. A12's only root is the test-only HMAC-SHA256 key; A15 records
  the same-party domain rather than inventing an external one.
* **No verified, externally domain-bound approval exists.** `APPROVALS.json` is
  empty. A production signing key, key distribution, a verification record and a
  real identity ceremony are A12/A16/A17 work.
* **The declarations are same-party.** `declaredBy` is the project's undeclared
  producer party (`P-CAMPAIGN`); A14 records `maintainer: none`, so no maintainer
  declared the thresholds. This is recorded, not remedied.
* **The establishment record's bytes are not re-read at evaluation time.** The
  domain record carries `{path, sha256}` and the producer computes the digest
  from the committed bytes, but the evaluator checks the record's shape and
  `independentOfCandidate` rather than recomputing the establishment digest.
  Binding the domain record to its bytes is A12/A16/A17 work.
* **The declarations' `n` is a policy quorum, not a measured population.** A15
  reports `availableDomains=0` rather than rewriting `n`; a future external
  domain enters the inventory as a record, not as a change to `n`.
* **The positive and alias controls are not real approvals.** They are labelled
  `control-only` and are excluded from the real aggregate.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## 11. `NOT_RUN`

* A real external trust domain, a real key ceremony and a real organisational
  identity.
* A real verified, externally domain-bound approval and a real approved action.
* A real threshold being met, a real release or claim promotion authorised by a
  threshold, and a real consumer graduation.
* A16 Sigstore bundles, A17 transparency and omission reconciliation, A18/A19
  where the queue names them.
* A BOUNDARY audit, a full Miri/ASan/TSan campaign, independent review and SEAL.
* The Rust suite: `src/` was not modified, so no rebuild and no `cargo test` is
  claimed.
