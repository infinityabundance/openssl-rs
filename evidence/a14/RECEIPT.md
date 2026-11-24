# A14 receipt — role-bound authorisation

## 1. Identity of this batch

| field | value |
|---|---|
| item | A14 (role-bound authorisation; a signature is not an authorisation; the seven roles; the six actions; the required separations) |
| branch | `staging` |
| HEAD at the start | `4e9262bf3` (`a11: freeze the scan population at a declared candidate`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 22 17 0 6 23` (total 45, used 22, free 17, available **23** GiB); `Swap: 45 31 14` |
| derived court cap | `min(8g, 23 - 16) = 7g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The derived cap is 7 GiB and the running container's cap is 6 GiB, which is
below it. The container was reused rather than restarted, as A7–A13 did. Every
reported gate is Python-only and ran in that court with
`PYTHONDONTWRITEBYTECODE=1` so the bind-mounted tree gained no `__pycache__`
entries. No test was edited, skipped, ignored or removed.

**Venue repair, recorded as history.** The court's login shell did not carry the
pinned tool paths, so the first whole-suite run read
`Ran 1207 tests in 216.858s`, `FAILED (failures=11, errors=1)`: ten
`instrument_qualify` controls failed with `binsec: command not found`, and
`test_binary_assurance` failed because `rustc`, `cargo` and `rustup` were not
on the login-shell `PATH`. This is a venue defect, not a repository defect. Four
symlinks were created **inside the disposable container** — `/usr/local/bin/{binsec,rustc,cargo,rustup}`
to the pinned opam/rustup binaries — with no repository change. The rerun read
`Ran 1207 tests in 219.159s`, `OK`. The check was not relaxed.

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/ROLE-AUTHORISATION.md` | 375 lines | normative document: the problem, the seven roles, the six actions and their separations, the algorithm order, the 13-code refusal table, the real result, the controls, the release-gate integration, non-claims, `NOT_RUN`, reproduction |
| `forensics/tools/authorisation.py` | 871 lines | the role vocabulary, the action policy, `authorise`, `roles_of`, `explain`, `separation_failures`, the CLI |
| `forensics/tools/tests/test_authorisation.py` | 690 lines | 51 controls: one per code, every separation individually, ordering, scope/validity, duplicate and alias, the real records, the positive control, determinism, CLI, document synchronisation |
| `forensics/tools/release_gate.py` | 1,300 lines | the minimal integration: item 7 `check_authorisation`, constants, CLI options, docstring and pass line |
| `forensics/tools/tests/test_release_gate.py` | 333 lines | 5 new controls for the authorisation row (refused, authorised, not-run, missing record, unparseable) |
| `evidence/a14/ROLES.json` | 244 lines / 8,867 bytes | the five real assignments, the two parties, the seven-role coverage, the real state (`releaseAuthority: none`, `externalReproducer: none`, `maintainer: none`, `instrumentReviewer: none`) |
| `evidence/a14/AUTHORISATION.json` | 952 lines / 33,101 bytes | the six actions, each with the recorded attempt and the labelled counterfactual role assessment, the separation failures, and the aggregate `authorised: 0` |
| `evidence/a14/CONTROLS.json` | 1,883 lines / 52,568 bytes | 13 refusal controls (one per code), the positive control, the `NOT_RUN` control and the alias control; every fixture `control-only` |
| `evidence/a14/build_evidence.py` | 804 lines | deterministic producer of the three records; asserts every control passes and the real aggregate is 0 |
| `evidence/a14/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A14 row only; no other row was touched.

## 3. The rule

> A signature is not an authorisation. It authorises an action only if the
> signer's identity holds the role the action requires, at the scope the action
> covers, at the time of the action, and the required separation of duties
> holds. A signature by the wrong role is insufficient, and one identity holding
> both sides of a separation is not two signatures.

The decision order is: action known → signature verified (before its role) →
identity recorded → role known → role assigned at the action time (expiry and
revocation) → scope → required role → self-authorisation → separation →
distinct signers. Distinct signers are counted by *party*, not by identity token:
`P-CAMPAIGN` and `P-PRINCIPAL` are both undeclared and are mapped to
`P-PROJECT-UNDECLARED`, so a second spelling is not a second signer.

## 4. The real roles

`evidence/etp-t8/ASSIGNMENTS.json` is the establishing record. It records 50
assignments, `same_party_adjudicator: 50`, 0 declared parties and 0 external
parties. The five real fills map to A14's roles as follows.

| identity token | where recorded | role | scope | real state |
|---|---|---|---|---|
| `P-CAMPAIGN` | `ASSIGNMENTS.json#parties.P-CAMPAIGN` | `producer` (author 50, evidence_producer 50, proof_producer 15, instrument_author 15) | `*` | same-party, undeclared |
| `P-CAMPAIGN` | `ASSIGNMENTS.json#summary` | `adjudicator` (50/50) | `*` | same-party, undeclared |
| `P-CAMPAIGN` | `ASSIGNMENTS.json#A-ADJ-B85C` | `external_reproducer` (the T8 `independent_reproducer` fill) | `claim:openssh-b85c` | **not external**; the record says it used this repository's environment and project artefacts |
| `P-PRINCIPAL` | `ASSIGNMENTS.json#A-REL-OPENSSH-B85C` | `release_authority` | `release:openssh-b85c` | undeclared; distinctness from `P-CAMPAIGN` not established |
| `P-CAMPAIGN` | `ASSIGNMENTS.json#A-REL-OPENSSH-B85C` | `revocation_authority` | `release:openssh-b85c` | same-party, undeclared |

No record establishes `maintainer` or `instrument_reviewer`. The T8 `reviewer`
fill (`RV-B85C-1`, role `"independent adversarial adjudicator"`) is the b85c
adjudication's reviewer, not an instrument reviewer.

Every assignment records `grantedBy` as `null`: no grantor identity, role,
account, organisation or signing key is recorded. The record does not invent
one.

The only recorded signing root is `test-only:hmac-sha256:8e10a5a15d233d54`
(A10/A12). It is symmetric and same-party, and it signs the A9 statements in the
A10 envelopes — not role authorisations. It establishes no identity.

**Summary: 5 real assignments, 2 undeclared party tokens, 0 declared identities,
0 external trust domains, `maintainer: none`, `instrumentReviewer: none`,
`externalReproducer: none`, `releaseAuthority: none`.**

## 5. The real authorisations

`evidence/a14/AUTHORISATION.json` attempts each action twice: `recorded` (the
role fills with `verified:false`, because no authorisation signature exists) and
`faceValue` (the same fills with `verified:true`, labelled
`COUNTERFACTUAL_ROLE_ASSESSMENT`; not a real signature).

| action | recorded outcome and codes | face-value codes | separation that failed |
|---|---|---|---|
| `release` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SEPARATION`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `release_authority` ≠ `producer`; `release_authority` ≠ `adjudicator`, all `P-PROJECT-UNDECLARED` |
| `claim-promotion` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SELF_AUTHORISATION`, `RA_REFUSED_SEPARATION` | `adjudicator` ≠ `producer` |
| `consumer-graduation` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SELF_AUTHORISATION`, `RA_REFUSED_SEPARATION`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `adjudicator` ≠ `producer`; `external_reproducer` ≠ `producer`; `adjudicator` ≠ `external_reproducer` |
| `instrument-qualification` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_ROLE_NOT_ASSIGNED`, `RA_REFUSED_WRONG_ROLE`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | not evaluable: no `instrument_reviewer` identity is recorded |
| `evidence-correction` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_ROLE_NOT_ASSIGNED`, `RA_REFUSED_WRONG_ROLE`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | not evaluable: no `maintainer` identity is recorded |
| `revocation` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SELF_AUTHORISATION`, `RA_REFUSED_SEPARATION` | `revocation_authority` ≠ `producer` |

**Aggregate: 0 actions authorised, 6 refused, 0 not run.** Both the recorded and
the face-value counts are **0 authorised**. The recorded attempt is refused at
the first stage because no authorisation signature exists; the face-value
assessment is still refused because every identity is the same undeclared party
or a required role is unassigned. This is the honest expected result, recorded
rather than worked around: no role label is promoted to a party, no second
spelling is counted as a second signer, and the test-only HMAC key is not
treated as an authorisation.

## 6. The controls

`evidence/a14/CONTROLS.json` holds 16 controls, all built in memory from
identities labelled `control-only`.

| control | code | result |
|---|---|---|
| `role-unknown` | `RA_REFUSED_ROLE_UNKNOWN` | fires |
| `role-not-assigned` | `RA_REFUSED_ROLE_NOT_ASSIGNED` | fires |
| `wrong-role` | `RA_REFUSED_WRONG_ROLE` | fires |
| `self-authorisation` | `RA_REFUSED_SELF_AUTHORISATION` | fires |
| `separation` | `RA_REFUSED_SEPARATION` | fires alone |
| `identity-unrecorded` | `RA_REFUSED_IDENTITY_UNRECORDED` | fires |
| `signature-unverified` | `RA_REFUSED_SIGNATURE_UNVERIFIED` | fires; `RA_REFUSED_ROLE_UNKNOWN` is absent, proving the ordering |
| `scope-exceeded` | `RA_REFUSED_SCOPE_EXCEEDED` | fires |
| `expired` | `RA_REFUSED_EXPIRED` | fires |
| `revoked` | `RA_REFUSED_REVOKED` | fires |
| `insufficient-signers` | `RA_REFUSED_INSUFFICIENT_SIGNERS` | fires |
| `duplicate-signer` | `RA_REFUSED_DUPLICATE_SIGNER` | fires |
| `action-unknown` | `RA_REFUSED_ACTION_UNKNOWN` | fires |
| `positive-distinct-roles` | — | three distinct synthetic parties reach `AUTHORISED`; **control-only**, not a real action |
| `not-run` | — | a declared-not-run action reports `NOT_RUN`, not a pass |
| `alias-is-one-signer` | — | two tokens of one party are one signer and one side of a separation |

The positive control establishes the decision procedure, not a real authorised
action; it is excluded from the real aggregate, which remains 0. The tests also
violate every declared separation constraint individually: 9 constraints across
the six actions, each refused with `RA_REFUSED_SEPARATION` naming that
constraint.

## 7. Release-gate integration

The gate has a per-refusal row structure: each checker returns
`Results(refusals, recorded)` and the gate combines rows without changing another
checker's verdict. A14 joins that seam as item 7 without touching items 1–6.

`check_authorisation` runs `forensics/tools/authorisation.py authorise release
--json` against `evidence/a14/AUTHORISATION.json` and `evidence/a14/ROLES.json`.
A refused or not-run decision is one row, `RG_AUTHORISATION_REFUSED`; an absent
tool or record is `RG_AUTHORISATION_TOOL_MISSING`, `RG_AUTHORISATION_MISSING` or
`RG_AUTHORISATION_ROLES_MISSING`; an unparseable result is
`RG_AUTHORISATION_ERROR`. A missing role check is never a skip.

**Before** (base tree, no A14 record; `--instrument-mode validate`):

```
release-gate: candidate 4e9262bf34e937439ec92bc832b5a569b27267b8; clean worktree (ignored paths excluded)
release-gate: REFUSED (31 item(s))
```

**After** (with the A14 record and the new item):

```
release-gate: candidate 4e9262bf34e937439ec92bc832b5a569b27267b8; 7 uncommitted path(s) (tracked or untracked; ignored paths excluded)
REFUSED RG_AUTHORISATION_REFUSED a14/release: outcome=REFUSED codes=RA_REFUSED_SIGNATURE_UNVERIFIED,RA_REFUSED_INSUFFICIENT_SIGNERS; face-value codes=RA_REFUSED_SEPARATION,RA_REFUSED_INSUFFICIENT_SIGNERS
release-gate: REFUSED (32 item(s))
```

The 31 existing refusals are unchanged; the A14 row is the 32nd. The
constitution mapping in `docs/RELEASE_GATES.md` §10 is **not** updated and is
retained as an obligation: the table still names Articles 5, 6, 7 and 9 as
uncovered and does not list the new row. The integration itself is done; the
mapping decision is not.

## 8. Defects found

**No gate rejected an existing record.** The whole suite was green at the base
after the venue repair (`Ran 1207 tests in 219.159s`, `OK`), and all gates are
green after the change (`Ran 1263 tests in 218.653s`, `OK`). The following
record-level omissions and contradictions were found and are preserved rather
than repaired, because repairing them would invent an identity ceremony or edit
another item's record.

| record | finding | treatment |
|---|---|---|
| `evidence/etp-t8/ASSIGNMENTS.json` | all 50 assignments have `identity: null`, `declared: false`, and no account, organisation or signing key; no grantor is recorded | recorded as `grantedBy: null`, `declaredIdentity: false` in `ROLES.json`; retained obligation |
| `evidence/etp-t8/ASSIGNMENTS.json#A-REL-OPENSSH-B85C` | `release_authority` is `P-PRINCIPAL`, whose distinctness from `P-CAMPAIGN` is not established | mapped to `P-PROJECT-UNDECLARED`; `releaseAuthority: none` |
| `evidence/etp-t8/ASSIGNMENTS.json#A-ADJ-B85C` | `independent_reproducer` is filled at `P-CAMPAIGN` and the record itself says it ran in this repository's environment on project artefacts | mapped to `external_reproducer` with `external: false`; `externalReproducer: none` |
| `evidence/etp-t8/ASSIGNMENTS.json#A-ADJ-B85C` | the `reviewer` fill (`RV-B85C-1`) is the b85c adjudication's reviewer, role `"independent adversarial adjudicator"`, not an instrument reviewer | no `instrument_reviewer` assignment; `instrumentReviewer: none` |
| `evidence/b85c-adjudication.json` | describes itself as an `independent adversarial adjudicator`; T8 records `same_party: SAME` and the fill at `P-CAMPAIGN` | the contradiction is preserved and the separation refusal is recorded; no record edited |

Four defects were found in this item's own new files and are preserved with the
old and new form. Each failed before a record was reported as green.

| file | old form | new form | found by |
|---|---|---|---|
| `evidence/a14/build_evidence.py` | the `self-authorisation` control signed `control-only-producer` as `adjudicator` without assigning that role, so it refused at `RA_REFUSED_ROLE_NOT_ASSIGNED` and never reached self-authorisation | the control adds the `adjudicator` assignment at `P-CONTROL-PRODUCER` | the producer's own assertion (`control self-authorisation failed`) |
| `evidence/a14/build_evidence.py` | the `duplicate-signer` control signed `control-only-alice` as `release_authority` without assigning it, so the duplicate code did not fire | the control adds the `release_authority` assignment at `P-CONTROL-ALICE` | the producer's own assertion (`control duplicate-signer failed`) |
| `docs/ROLE-AUTHORISATION.md` | the release-gate enforcement line split `Enforced by` from the `RG_AUTHORISATION_REFUSED`/test name onto a second line | the code, path and test name are on the same line | `test_every_enforced_by_names_a_code_or_test` |
| `forensics/tools/tests/test_authorisation.py` | the positive-control assertion searched for a newline inside a one-line phrase | the assertion searches for `not a real authorised action` | that test's first run |

## 9. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 22 17 0 6 23` (available 23 GiB); `Swap: 45 31 14` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1263 tests in 218.653s`; `OK`; `closure discipline self-test: 7 control groups passed`. **1,207 pre-existing tests are present** (1,207 + 56 = 1,263), **none ignored** |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `ROLES.json`, `AUTHORISATION.json`, `CONTROLS.json` | `ok` for all three, exit 0 each |
| producer, two runs | `python3 evidence/a14/build_evidence.py --out /tmp/a14c --source-commit 4e9262bf34e937439ec92bc832b5a569b27267b8` and the same to `/tmp/a14d` | `a14: assignments=5 roles=7 actions=6 authorised=0 refused=6 codes=13 controls=16 commit=4e9262bf3` twice |
| producer byte-identity | `cmp` of `/tmp/a14c/<name>`, `/tmp/a14d/<name>` and `evidence/a14/<name>` | `identical` for `ROLES.json`, `AUTHORISATION.json` and `CONTROLS.json` |
| the six real actions | `python3 forensics/tools/authorisation.py authorise <action>` | exit 1 for all six; each `outcome=REFUSED codes=RA_REFUSED_SIGNATURE_UNVERIFIED,RA_REFUSED_INSUFFICIENT_SIGNERS`; aggregate **0 authorised** |
| the face-value assessment | `authorise <action> --json` | `release` separation+insufficient; `claim-promotion` self+separation; `consumer-graduation` self+separation+insufficient; `instrument-qualification` and `evidence-correction` role-not-assigned+wrong-role+insufficient; `revocation` self+separation; **0 authorised** |
| release gate before | `python3 forensics/tools/release_gate.py --instrument-mode validate` | `release-gate: REFUSED (31 item(s))`, exit 1, on a clean worktree |
| release gate after | the same command with the A14 record | `REFUSED RG_AUTHORISATION_REFUSED a14/release: ...`; `release-gate: REFUSED (32 item(s))`, exit 1; the 31 existing refusals unchanged |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `M forensics/tools/release_gate.py`, `M forensics/tools/tests/test_release_gate.py`, `?? docs/ROLE-AUTHORISATION.md`, `?? evidence/a14/`, `?? forensics/tools/authorisation.py`, `?? forensics/tools/tests/test_authorisation.py` |

**Reproducibility.** The producer reads the bytes of the T8 assignment and role
records, the A12 trust-root inventory, the A10 envelope record and the two b85c
records; every digest is computed from bytes. Two runs are byte-identical and the
committed files match a fresh build, enforced by
`test_builder_is_byte_identical_twice_and_matches_committed` and
`test_build_is_deterministic_in_process`. The source identity is supplied
(`--source-commit`); without it the recorded `BASE_COMMIT` is reused, never a
live `HEAD`.

## 10. Obligations retained

* **`docs/RELEASE_GATES.md` §10 is not updated.** The gate runs the new row, but
  the constitution's gate-item table does not list it and still names Articles 5,
  6, 7 and 9 as uncovered. Deciding which article the authorisation row
  evidences, and updating the table, is a separate change.
* **No real authorisation signature exists.** Every recorded attempt is
  `verified:false`; a production signing key, key distribution and a
  verification record are A12/A16/A17 work.
* **No external role holder exists.** No maintainer, instrument reviewer,
  external reproducer or declared release authority is established by a tracked
  record. A14 records `none` and does not create them.
* **No grantor is recorded in T8.** The 50 assignments name no grantor identity,
  role, account, organisation or signing key; `grantedBy` is null rather than
  invented.
* **The positive control is not a real action.** It is labelled `control-only`
  and is excluded from the real aggregate.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## 11. `NOT_RUN`

* A cryptographic signature verification, a production signing key, key
  distribution, revocation distribution and a real identity ceremony.
* A real maintainer, instrument reviewer, external reproducer or declared
  release authority.
* A real authorised release, claim promotion, consumer graduation, instrument
  qualification, evidence correction or revocation.
* A15 thresholds, A16 Sigstore bundles, A17 transparency and the release gate's
  package and documentation items.
* A BOUNDARY audit, a full Miri/ASan/TSan campaign, independent review and SEAL.
* The Rust suite: `src/` was not modified, so no rebuild and no `cargo test`
  is claimed.
