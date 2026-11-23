# ETP-T12 receipt — public verification interface

**Status:** `DONE` for the interface, the controls and the clean-checkout
demonstration. **The run is red, and that is the result:** 8 of 19 steps pass,
9 fail, 2 are `NOT_RUN`, and `verify all` exits 1. No requirement was lowered to
change that.

**Source identity (`S`):** `6c174518e9cc38eb5f036ea9071c9be25e35e98a`, branch
`staging`, tree `0c5fcee3037f32fcc955daeab822f018c67f9b80`, 0 tracked changes at
the start of the batch. (`git --no-pager rev-parse HEAD`, `git status
--porcelain`.)

**Deliverables:** `forensics/tools/verify.py`, `forensics/tools/tests/test_verify.py`,
`docs/PUBLIC-VERIFICATION.md`, `evidence/etp-t12/RUN.json` (validated with
`python3 -m json.tool`), this receipt, and the `docs/ETP-TODO.md` row.

---

## 1. Venue and resource bound

`free -g` before any command: **available 23 GiB**, swap 1 GiB free of 45 GiB.
The §6.1 cap is `min(8g, 23 − 16) = 7g` with a 2g floor, so every command ran in
the court with:

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1
OPENSSL_RS_COURT_MEM=7g OPENSSL_RS_COURT_MEMSWAP=7g
bash docker/openssl-rs-court.sh exec sh -c '<command>'
```

Inside the court: Python 3.11.2, git 2.39.5, cargo 1.98.1, 30 CPUs. No Rust
build was run. **No build was permitted:** available stayed below the 24 GiB
floor, so `rebuild` and `differential` refused themselves with that reason rather
than starting a compiler under a cap this session could not justify.

## 2. The demonstration checkout

A fresh clone was made **inside the court's bind mount**, from the repository at
`S`:

```
git -c safe.directory=/work clone --no-hardlinks /work /work/court/tmp/t12/clean
git -C /work/court/tmp/t12/clean remote remove origin
```

* HEAD `6c174518e`, 0 tracked changes;
* `git status --porcelain --ignored=matching` reports **two untracked files** —
  the two new scripts (`forensics/tools/verify.py`,
  `forensics/tools/tests/test_verify.py`) — and **no ignored or private entry**;
* the checkout has **no** `court/tmp/`, `target/`,
  `forensics/authorities/prefix/` or `forensics/authorities/downloads/` content.
  (`court/` itself exists because 278 of its files are tracked; the interface
  reports them as `tracked_files: 278, private_entries: 0`, not as private
  state.)
* `origin` was removed so no step can reach the development checkout; nothing in
  the run fetched.

The two untracked files are the deliverables the orchestrator is asked to commit;
they are not private state and no step needs them to be tracked. A run at the
committed identity would report `untracked_changes: 0` and the same verdicts,
because no delegate reads either file except `controls` (which discovers
`test_verify.py` as an ordinary test module) and the interface itself.

The venue runs as root over a checkout owned by uid 1000, so the court's
`/etc/gitconfig` `safe.directory=/work` does not cover the clone. The run
therefore set `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory`,
`GIT_CONFIG_VALUE_0=/work/court/tmp/t12/clean` — a venue setting, not repository
content. Without it Git refuses with `fatal: detected dubious ownership in
repository at '/work/court/tmp/t12/clean'` and the first probe of `claims`
reported 77 `EG_EVIDENCE_CHECK_UNAVAILABLE` refusals, which is an environment
artefact rather than a claim-set defect; the run below is with the setting set.

Fresh `HOME=/tmp/t12home2` and `TMPDIR=/tmp/t12tmpA` (or `…B` for the second
run) were created empty before each run.

## 3. The clean-checkout run, verbatim

Command:

```
cd /work/court/tmp/t12/clean
HOME=/tmp/t12home2 TMPDIR=/tmp/t12tmpA \
  python3 forensics/tools/verify.py all
```

Exit status: **1**.

```
openssl-rs public verification
interface  ETP-T12 (openssl-rs/verify/1)
candidate  6c174518e9cc38eb5f036ea9071c9be25e35e98a [staging] clean=True (tracked) untracked=2
root       /work/court/tmp/t12/clean
network    not declared (offline)
private    no untracked or ignored entries under the declared roots

[ 1/19] manifest       FAIL    (required)  REFUSED: the staged tree does not match the frozen manifest. (56 hard refusal(s) against evidence/etp6/MANIFEST.json at this commit)
        python3 forensics/tools/etp6_package.py --commit HEAD --out {tmp}/etp6-package -> exit 2 (FAIL)
[ 2/19] rebuild        NOT_RUN (required)  requires memory:24: MemAvailable 22 GiB is below the 24 GiB floor AGENTS.md section 6.1 requires before a build
[ 3/19] proofs         PASS    (required)  the reference regenerates every tracked vector byte-for-byte and the difference classifier passes its own controls
        python3 make_vectors.py --check -> exit 0 (PASS)
        python3 driver.py --self-test -> exit 0 (PASS)
[ 4/19] differential   NOT_RUN (required)  requires memory:24: MemAvailable 22 GiB is below the 24 GiB floor AGENTS.md section 6.1 requires before a build
[ 5/19] instruments    PASS    (required)  the register validates and every requested executable control passed in the venue that ran it
        python3 forensics/tools/instrument_qualify.py check -> exit 0 (PASS)
[ 6/19] controls       FAIL    (required)  Ran 451 tests in <elapsed>; FAILED (failures=3); first: FAIL: test_check_output_is_deterministic (test_spec_guard.SpecGuardControls.test_check_output_is_deterministic)
        python3 -m unittest discover -s tests -p test_*.py -> exit 1 (FAIL)
[ 7/19] receipts       PASS    (required)  every receipt parses, every withdrawal names its successor, and every manifest log exists with the recorded digest
        python3 courts/phase18/interop/check_receipts.py --summary -> exit 0 (PASS)
[ 8/19] claims         PASS    (required)  the committed claim set passes the schema, the cross-field laws and the Git-bound digest re-derivation
        python3 forensics/tools/etp_claims.py validate -> exit 0 (PASS)
[ 9/19] freshness      FAIL    (required)  status REFUSED; 331 artefact(s) (HISTORY=81, INVALIDATED=92, UNAFFECTED=31, UNRESOLVED=127); 267 refusal(s); first: FR_CARRY_FORWARD_UNDECLARED at courts/phase17/downstream/curl/result.json
        python3 forensics/tools/freshness.py check -> exit 1 (FAIL)
[10/19] independence   FAIL    (required)  13 refusal(s); first: REFUSED IND_ADJUDICATOR_IS_AUTHOR assignment=A-ADJ-B85C field=filled.adjudicator|filled.author: adjudicator and author are not distinct at same_agent (recorded same_agent=SAME, same_organisation=SAME, same_infrastructure=SAME, same_key=SAME)
        python3 forensics/tools/independence.py check -> exit 1 (FAIL)
[11/19] closure        FAIL    (required)  2 aggregate refusal(s) (safe-compatible-openssh-b85c, campaign-status); 31 opaque row(s) unscoped
        python3 forensics/tools/closure_discipline.py check -> exit 1 (FAIL)
[12/19] scheduling     FAIL    (required)  status REFUSED over 6 change set(s) and 78 requirement(s) (BLOCKED=0, FAILED=0, NOT_RUN=59, REFUSED=19, SATISFIED=0)
        python3 forensics/tools/scheduling.py report --change-sets evidence/etp-t11/CHANGE-SETS.json --runs evidence/etp-t11/RUNS.json --store evidence/etp-t11/CACHE.json -> exit 1 (FAIL)
[13/19] traceability   PASS    (required)  the graph validates and every declared orphan is reproduced
        python3 forensics/tools/traceability.py validate -> exit 0 (PASS)
[14/19] hazards        PASS    (required)  the register validates and every projected field and edge matches the graph
        python3 forensics/tools/hazard_register.py validate -> exit 0 (PASS)
[15/19] binary         PASS    (required)  the TCB validates and no claim crosses a target, profile or TCB boundary
        python3 forensics/tools/binary_assurance.py check -> exit 0 (PASS)
[16/19] docs           PASS    (required)  every checked quantity in the documents agrees with its generated source
        python3 forensics/tools/docs_consistency.py -> exit 0 (PASS)
[17/19] consumer-curl  FAIL    (required)  43 of 420 exclusion row(s) fail
        python3 forensics/tools/closure_discipline.py audit --receipt evidence/closure-curl-049.json -> exit 1 (FAIL)
[18/19] consumer-ssh   FAIL    (required)  374 of 374 exclusion row(s) fail; the recorded inventory court/freeze-b85/census-b85.json is absent (private state)
        python3 forensics/tools/closure_discipline.py audit --receipt evidence/closure-ssh-b85c.json -> exit 1 (FAIL)
[19/19] consumer-sshd  FAIL    (required)  327 of 327 exclusion row(s) fail; the recorded inventory court/freeze-b85/census-b85.json is absent (private state)
        python3 forensics/tools/closure_discipline.py audit --receipt evidence/closure-sshd-b85c.json -> exit 1 (FAIL)

RESULT: FAIL (8/19 steps PASS)
not PASS:
  manifest: FAIL: REFUSED: the staged tree does not match the frozen manifest. (56 hard refusal(s) against evidence/etp6/MANIFEST.json at this commit)
  rebuild: NOT_RUN: requires memory:24: MemAvailable 22 GiB is below the 24 GiB floor AGENTS.md section 6.1 requires before a build
  differential: NOT_RUN: requires memory:24: MemAvailable 22 GiB is below the 24 GiB floor AGENTS.md section 6.1 requires before a build
  controls: FAIL: Ran 451 tests in <elapsed>; FAILED (failures=3); first: FAIL: test_check_output_is_deterministic (test_spec_guard.SpecGuardControls.test_check_output_is_deterministic)
  freshness: FAIL: status REFUSED; 331 artefact(s) (HISTORY=81, INVALIDATED=92, UNAFFECTED=31, UNRESOLVED=127); 267 refusal(s); first: FR_CARRY_FORWARD_UNDECLARED at courts/phase17/downstream/curl/result.json
  independence: FAIL: 13 refusal(s); first: REFUSED IND_ADJUDICATOR_IS_AUTHOR assignment=A-ADJ-B85C field=filled.adjudicator|filled.author: adjudicator and author are not distinct at same_agent (recorded same_agent=SAME, same_organisation=SAME, same_infrastructure=SAME, same_key=SAME)
  closure: FAIL: 2 aggregate refusal(s) (safe-compatible-openssh-b85c, campaign-status); 31 opaque row(s) unscoped
  scheduling: FAIL: status REFUSED over 6 change set(s) and 78 requirement(s) (BLOCKED=0, FAILED=0, NOT_RUN=59, REFUSED=19, SATISFIED=0)
  consumer-curl: FAIL: 43 of 420 exclusion row(s) fail
  consumer-ssh: FAIL: 374 of 374 exclusion row(s) fail; the recorded inventory court/freeze-b85/census-b85.json is absent (private state)
  consumer-sshd: FAIL: 327 of 327 exclusion row(s) fail; the recorded inventory court/freeze-b85/census-b85.json is absent (private state)
```

The same run with `--json` is `evidence/etp-t12/RUN.json`
(SHA-256 `e199607d575710c65215ed33735fbeaab49935c5bbb25139a21540b8f55ea91f`),
validated with `python3 -m json.tool`. It records per step the status, the
reason, the evidence identity (path and SHA-256, or `absent`), the delegate's
digest, the prerequisites resolved, the declared private paths and their observed
state, and each command with its exit status.

## 4. What each non-pass is, and is not

| step | status | what the interface reports |
|---|---|---|
| `manifest` | FAIL | the tracked ETP-6 manifest at `evidence/etp6/MANIFEST.json` names candidate `98c7b5d290a8…`; this checkout is `6c174518e…`, so 56 of its inputs no longer have the recorded digest. The manifest is stale with respect to this candidate; the interface does not repair it and does not treat "the files exist" as agreement. |
| `rebuild` | NOT_RUN | §6.1's 24 GiB floor was not met (22 GiB observed at check time). A reproducibility result is not claimed. |
| `differential` | NOT_RUN | same floor. The authority prefix is also absent (`forensics/authorities/prefix` is gitignored), so even with memory this step could not run here. |
| `controls` | FAIL | 451 tests, 3 failures: `test_spec_guard.test_check_output_is_deterministic`, `test_spec_guard.test_committed_registry_passes`, `test_unsafe_obligations.test_committed_inventory_and_axioms_validate`. The unmodified clone (no `test_verify.py`) runs 432 tests and fails the same three with the same assertions (`SP_KNOWN_FAILURE_DRIFT` on `docs/ETP-TODO.md` for the tokens `OPENSSL_clear_free` and `guard_ffi`, and `ET4_SOURCE_DRIFT`). The new module therefore adds 19 passing tests and no failure, and the ETP-T12 row adds no flagged token. |
| `freshness` | FAIL | 267 `FR_CARRY_FORWARD_UNDECLARED` refusals (first: `Cargo.lock` moved since the citing artefact); verdicts `HISTORY=81, INVALIDATED=92, UNAFFECTED=31, UNRESOLVED=127` over 331 artefacts. |
| `independence` | FAIL | 13 refusals; first: `A-ADJ-B85C`'s adjudicator and author are the same agent. That is the b85c graduation defect, reported rather than smoothed. |
| `closure` | FAIL | two aggregates report a pass while containing a blocked row (`safe-compatible-openssh-b85c`, `campaign-status`), and 31 opaque rows are unscoped. |
| `scheduling` | FAIL | 78 requirements over 6 change sets: 59 `NOT_RUN`, 19 `REFUSED`, 0 `SATISFIED`. Refusals are incomplete applicability identities, not deferrals. |
| `consumer-curl` | FAIL | 43 of 420 exclusion rows fail. This is ETP-T10's own recorded figure (420/43) and is reproduced here in a checkout without private state. |
| `consumer-ssh` | FAIL | 374 of 374 rows fail because the inventory the receipt cites (`court/freeze-b85/census-b85.json`) is absent. In the development tree, where that private census exists, the same audit reports 337 of 374 failing — the private-state difference is visible in the verdict rather than hidden. |
| `consumer-sshd` | FAIL | 327 of 327 rows fail for the same absent inventory (290 of 327 with the census present). |

Each of these is the delegated tool's verdict at this candidate, bound to the
tool and evidence digests in `RUN.json`. None is a new defect declared by this
interface, and none is repaired here.

## 5. The six required controls, observed

| # | control | observation |
|---|---|---|
| 1 | a missing tool is `NOT_RUN`, not silently skipped | `test_missing_tool_is_not_run_and_named` and `test_missing_tool_is_not_run_end_to_end` remove a delegate and observe `NOT_RUN` with the tool path in the reason. `verify --list` names every subcommand whether or not its delegate exists. |
| 2 | a non-zero status is `FAIL`, not `PASS` | `test_exit_zero_is_pass_and_non_zero_is_fail`; observed end to end in `manifest` (exit 2 → FAIL) and `controls` (exit 1 → FAIL). |
| 3 | a network step is `NOT_RUN` offline and says so | `verify authority` → `NOT_RUN: requires network: … the run declares none (pass --network …)`; `test_network_step_is_refused_offline` and `test_network_step_runs_when_declared`. `--network` is a declaration, never a probe. |
| 4 | `verify all` propagates any non-pass | exit **1** with 11 non-passing steps named; `test_all_propagates_a_non_pass_and_names_every_step` and `test_single_optional_step_cannot_exit_zero_while_not_pass`. |
| 5 | a private-state dependency is detected and reported, not silently satisfied | the clean run reports `private: no untracked or ignored entries under the declared roots` and the consumer rows fail on the absent census; the development-tree run reports `court` with 213 private entries and the audits return the smaller failure counts. The difference is in the output, not in a footnote. |
| 6 | a claim or receipt with missing evidence is `FAIL` | `consumer-ssh`/`consumer-sshd` FAIL naming the absent inventory; `test_drifted_receipt_is_fail_end_to_end` edits a receipt and observes `FAIL` with the digest mismatch; `test_absent_receipt_is_fail_not_not_run`. |

Interface self-controls: `python3 forensics/tools/tests/test_verify.py` →
**19 tests, OK** (13 decision-level controls with an injected executor, 6
end-to-end controls in a throwaway stub tree).

## 6. Determinism

Two `--json` runs of `all` from the same checkout, with separate fresh `TMPDIR`s:

```
cmp /tmp/t12-run-a.json /tmp/t12-run-b.json   # byte-identical
```

No timestamp is emitted, every list is sorted on a documented key, `tmpdir` is
recorded as `<tmp>`, and the normaliser replaces the checkout path, temporary
paths and elapsed times before they enter the document. `RUN.json` is the first
of the two.

## 7. What this interface cannot verify

* It cannot make a red tool green. Nine steps fail because their delegates refuse
  at this candidate; the interface reports that, and a green result would require
  the underlying defects to be repaired, not the gate to be relaxed.
* It cannot establish any claim's truth. Every step's verdict is the delegate's;
  `binary` in particular passes while reporting four unbound claims, and
  `claims` passes while the claim set contains `CONTRADICTED` members.
* It cannot reproduce a build or run the authority differential in this venue:
  `rebuild` and `differential` are `NOT_RUN`, so no reproducibility,
  source-to-binary or three-way cryptographic agreement is claimed here.
* It cannot give an external party a distinctness it does not have:
  `independence` fails, and the interface does not substitute its own judgement.
* It cannot prove that a delegate never reads private state. The declarations and
  the observed private-entry counts are the audit surface; a read outside them
  would be a defect in that delegate, and the report would not detect it.
* It cannot verify its own interpreter, the court image or the host kernel. The
  tool digests bind the verdicts to the scripts, not to the runtime.

## 8. Non-claims

No `src/`, `docker/` or build change was made. No obligation is discharged by
this batch. The interface is not a security boundary and not a sandbox. The
`controls` failure predates this change and is not repaired here. The
`freshness`, `independence`, `closure`, `scheduling` and consumer failures are
the tools' recorded state of the campaign, not measurements introduced by this
interface.
