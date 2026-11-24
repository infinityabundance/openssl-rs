# ETP-7 — continuous enforcement in CI and release tooling

**Candidate:** branch `staging`, HEAD `8a697aa7ea993e4e25ef38351b51d6b24148606c`,
2026-11-22. The gate was run against this tree before the ETP-7 files were
committed; the six uncommitted paths it reports are the ETP-7 edits to
`.github/workflows/ci.yml`, `docs/{CI,RELEASE_GATES,ETP-TODO}.md`, the new
`forensics/tools/release_gate.py` and the new `evidence/etp7/`. No `src/` file,
campaign raw data or another item's evidence was changed.

**Record status (2026-11-23).** This receipt records two identities, and they
are not interchangeable. §1–§8 describe the item and the gate as they were at
HEAD `8a697aa7e`. The verbatim transcript in §3 and the table in §5 are that
run; they are **superseded** and are preserved unedited as history. §9 records
the same gate at candidate `2d31a23fb`, where the claim set conjoins to
`SUPERSEDED` with 37 open obligations and where the refusals are identity-triage
and package refusals, not the four `RG_CLAIM_CONTRADICTED` items. A reader who
needs the current result reads §9; a reader who needs the run that introduced the
gate reads §3.

**Venue:** `openssl-rs-court-tools:1`, existing container, 8 GiB memory cap,
8 CPUs. Host `free -g` before the first command: total 45, used 17, free 20,
available 28 GiB (the section 6.1 guard requires at least 24 GiB). Every
command below ran in the court; nothing compiled on the host. One heavy command
ran at a time.

This receipt records what was executed and what was only syntax-checked. It is
not a safety, compatibility or cryptographic result, and the gate's PASS would
not be one either (`AGENTS.md` section 8).

---

## 1. Inventory before ETP-7

| artefact | what it ran | what it did not run |
|---|---|---|
| `.github/workflows/ci.yml` (`lint`) | clippy with `-D warnings` | formatting (it was in `static`) |
| `.github/workflows/ci.yml` (`adversarial`) | `scripts/adv-probe.sh` | — |
| `.github/workflows/ci.yml` (`static`) | fmt, release build, serial `cargo test --lib`, default-thread `cargo test --lib`, forbidden backends, no dependencies, determinism, symbol ownership, prerequisite/plan gates, evidence portability, regression guard (seal refs) | the Python assurance gates; `--test-threads=4` was implicit, not named |
| `.github/workflows/ci.yml` (`courts`, seal refs) | court image, authority build, every stratum's courts, probe hygiene, re-derived regression guard | instrument qualification (the base court image has no valgrind/BINSEC/dudect) |
| `.github/workflows/container.yml` | publishes the court image to `ghcr.io` on `v*` tags | nothing release-claiming; a published image is not a result |
| release path | manual `cargo publish`, documented in `docs/RELEASE_GATES.md` | any machine check; no release script, no tag-triggered publish |

**Where a gate could be bypassed.** (a) Nothing tied a tag or `cargo publish` to
a check, so a maintainer could publish with the claim set contradicted. (b) The
assurance gates (`etp_claims.py`, `check_receipts.py`, `docs_consistency.py`, the
benchmark analyser's controls) ran only when a person typed the command. (c) The
`--test-threads=4` tier was the runner default, so its meaning depended on the
machine. (d) No single decision combined the claim set, the receipts, the
instrument register, a real package and the documents; each was a separate
command with no conjunction.

---

## 2. What was added

### `forensics/tools/release_gate.py` (new, standard library only)

Six required items, in order. One refusal refuses the release; a missing tool,
missing package or unreadable input is a refusal, never a skip.

| item | checker | refusal rules |
|---|---|---|
| candidate identity | `git rev-parse` | `RG_CANDIDATE_UNRESOLVED`, `RG_CANDIDATE_NOT_CHECKED_OUT`, `RG_CANDIDATE_DIRTY` (`--require-clean`) |
| claim set | `etp_claims.py validate` + `conjoin`, and the gate's own state scan | `RG_CLAIMS_INVALID`, `RG_CLAIMS_MISSING`, `RG_CLAIM_TOOL_FAILED`, `RG_CLAIM_CONTRADICTED`, `RG_CLAIM_REFUTED`, `RG_CLAIM_WITHDRAWN`, `RG_CLAIM_NOT_ESTABLISHED`, `RG_CLAIM_WITHDRAWN_EVIDENCE`, `RG_CLAIM_CONJOIN_FAILED` |
| interop receipts | `courts/phase18/interop/check_receipts.py --dir … --summary` | `RG_RECEIPT` (one per R1–R5 problem), `RG_RECEIPT_DIR_MISSING`, `RG_RECEIPT_TOOL_MISSING` |
| instrument register | `instrument_qualify.py check --registry …` | `RG_INSTRUMENT` (one per refusal code), `RG_INSTRUMENT_REGISTRY_MISSING`, `RG_INSTRUMENT_TOOL_MISSING` |
| external package | the package's own `verify.sh` or `forensics/tools/etp6_verify.py` | `RG_PACKAGE_MISSING`, `RG_PACKAGE_INVALID`, `RG_PACKAGE` (one per failing step line) |
| documentation | `docs_consistency.py` | `RG_DOCS` (one per `STALE:` line), `RG_DOCS_TOOL_MISSING` |

`--package` accepts an unpacked package root or the `.tar.gz`; archives are
unpacked with absolute paths, `..`, links and devices refused. `--json` emits
the same decision for retention. `--self-test` is the negative-control suite.

### `.github/workflows/ci.yml`

- `lint`: `cargo fmt --all -- --check` now runs before clippy, so the FAST order
  is formatting then lints.
- `static`: the parallel-safety test is now
  `cargo test --lib -- --test-threads=4`, the tier's thread count named
  explicitly rather than inherited from the runner.
- new `assurance` job, every push/pull request, in this order:
  `etp_claims.py validate`; `etp_claims.py conjoin` (recorded, expected to read
  `CONTRADICTED` while ETP-T15 is open, deliberately not gating);
  `check_receipts.py`; `docs_consistency.py` and a checked `--self-test` verdict
  (`ok` passes, `skipped` is `NOT_RUN` with a warning, anything else fails);
  `tests/test_analyse_bench_api.py`; `tests/test_etp_claims.py`;
  `release_gate.py --self-test`; and an inline assertion that the three unsafe
  lint attributes in `Cargo.toml` and `src/lib.rs` are preserved.

### Documentation

- `docs/CI.md`: the FAST tier table, the exact command per item, and the checks
  the tier does **not** run with the reason (instrument register, full section 6
  structural guards, the release gate itself).
- `docs/RELEASE_GATES.md`: the gate's six items, the command, the policy that a
  release without a passing gate is a violation, the retention of its output, and
  the named gap that no tag/publish path invokes it automatically.
- `docs/ETP-TODO.md`: the ETP-7 row.

---

## 3. The gate's actual output on this tree

**Superseded (A0-F06, 2026-11-23).** The command and output below are the run
at `8a697aa7e`. The numbers in them are not edited: they record what the gate
produced at that identity. The live run is §9.

Package: built from HEAD by
`python3 forensics/tools/etp6_package.py --out /tmp/etp6-drift-check`, unpacked
to `/tmp/pkg-etp7`, whose own verifier passes:

```
RESULT: PASS (5/5 required steps PASS)
```

Command, verbatim:

```
python3 forensics/tools/release_gate.py --package /tmp/pkg-etp7
```

Output, verbatim (exit 1):

```
release-gate: candidate 8a697aa7ea993e4e25ef38351b51d6b24148606c; 6 uncommitted path(s) (tracked or untracked; ignored paths excluded)
release-gate: claim ETP0-CLM-033: verdict SUPERSEDED (recorded, not a release block)
release-gate: claim conjunction: CONTRADICTED
release-gate: claim source identity: 9372bb28b2fbe2f71cf2aa2ab501414d45e87d42
release-gate: receipt  RECEIPT-o10.json             live
release-gate: receipt  RECEIPT-o12.json             live
release-gate: receipt  RECEIPT-o2.json              live
release-gate: receipt  RECEIPT-o3.json              live
release-gate: receipt  RECEIPT-o4.json              live
release-gate: receipt  RECEIPT-o5.json              live
release-gate: receipt  RECEIPT-o6.json              live
release-gate: receipt  RECEIPT-o7-AA.json           live
release-gate: receipt  RECEIPT-o7-AB.json           live
release-gate: receipt  RECEIPT-o7-BA.json           live
release-gate: receipt  RECEIPT-o7-BB.json           live
release-gate: receipt  RECEIPT-o7.json              live
release-gate: receipt  RECEIPT-o8.json              live
release-gate: receipt  RECEIPT-o9.json              live
release-gate: manifest MANIFEST-o11-A.json          log=present
release-gate: manifest MANIFEST-o11-B.json          log=present
release-gate: receipts=14 manifests=2 problems=0
release-gate: QUALIFICATION ok: every requested control passed and matched the register
release-gate: package /tmp/pkg-etp7: RESULT: PASS (5/5 required steps PASS)
release-gate: [docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources
REFUSED RG_CLAIM_CONTRADICTED ETP0-CLM-004: verdict CONTRADICTED -- artifacts/phase18/COURTS.json at S records all_pass false, summary pass 4 / fail 1, with HOSTILE-BOUNDARY-REGISTER failing on 56 unsafe-footprint bounds. forensics/phase18-obligations.json at S records implemented 4 and open_in_this_stratum 1 (hostile-boundary-register, state open, measurement not_measured).
REFUSED RG_CLAIM_CONTRADICTED ETP0-CLM-005: verdict CONTRADICTED -- courts/phase18/ct_primitives_probe.c defines SEP_PCT 150; artifacts/phase18/COURTS.json records threshold_percent 150; the seal prose is internally inconsistent (110 vs 50 vs 150). The probe source and machine record agree; the prose does not.
REFUSED RG_CLAIM_CONTRADICTED ETP0-CLM-030: verdict CONTRADICTED -- The claim's own cited closure receipts record verdict.safe_compatible=false; FREEZE-b85c.json records the L7 replay as not_graduated; the independent b85c adjudication (also preserved by this record) records NOT ESTABLISHED. The graduation is a principal risk acceptance, not an evidence-derived SAFE_COMPATIBLE verdict, and the record says so.
REFUSED RG_CLAIM_CONTRADICTED ETP0-CLM-032: verdict CONTRADICTED -- CAMPAIGN-STATUS.json records consumers.safe_compatible = 1 and safe_compatible_graduation.verdict = SAFE_COMPATIBLE, while its own consumers.note says SAFE_COMPATIBLE remains 0/33 and non_claims[0] says no consumer family is SAFE_COMPATIBLE. PROGRESS.md says the counter is not advanced. STATUS-2026-10-20.md says 1/33.
release-gate: REFUSED (4 item(s))
```

**Why the refusal is the correct result.** The committed claim set contains four
`CONTRADICTED` members (ETP0-CLM-004, -005, -030, -032). Each is a tracked
disagreement between the seal prose and the machine record, or between the
graduation record and the closure/adjudication it cites. No gate may turn those
into a release; ETP-T15 owns their reconciliation. The other five items pass:
candidate identity, receipts (14 receipts, 2 manifests, 0 problems), the
instrument register (every executable control PASS or RECORDED, none NOT_RUN),
the package verifier (5/5), and documentation (20 claims). A release at this
candidate is correctly blocked on the claim set alone.

The no-package run is the other required control. With no `--package`, the same
command exits 1 and adds:

```
REFUSED RG_PACKAGE_MISSING -: no --package was supplied; the ETP-6 external-package verifier is a required release item, so an absent package is a refusal
```

That is the item that would otherwise be skipped by a release checklist.

The release procedure uses `--require-clean`, which also refuses an uncommitted
working tree because `cargo publish` packages the working tree, not the commit.
On this pre-commit tree that control fires independently of the claims:

```
REFUSED RG_CANDIDATE_DIRTY 8a697aa7ea993e4e25ef38351b51d6b24148606c: 6 uncommitted path(s); a release is evaluated from a committed tree, because `cargo publish` packages the working tree:  M .github/workflows/ci.yml,  M docs/CI.md,  M docs/ETP-TODO.md,  M docs/RELEASE_GATES.md, ?? evidence/etp7/, ?? forensics/tools/release_gate.py
```

After the orchestrator commits, the identity line reads `clean worktree`; the four
claim refusals remain, which is the result that matters.

---

## 4. Self-test, per failure class

Command:

```
python3 forensics/tools/release_gate.py --self-test
```

Output, verbatim (exit 0):

```
  ok   contradicted claim: expected RG_CLAIM_CONTRADICTED
  ok   withdrawn-evidence claim: expected RG_CLAIM_WITHDRAWN_EVIDENCE
  ok   failing receipt: expected RG_RECEIPT
  ok   invalid instrument register: expected RG_INSTRUMENT
  ok   missing package: expected RG_PACKAGE_MISSING
  ok   failing package verifier: expected RG_PACKAGE
  ok   documentation inconsistency: expected RG_DOCS
  ok   real documentation checker (positive control): expected no refusal
release-gate self-test: ok (8 cases)
```

The fixtures are built in a temporary directory from the committed claim
document, so the test does not depend on the current verdicts. The claim,
receipt, instrument and package cases call the real checkers. The documentation
case drives the gate's adapter with a checker that prints a stale claim, because
`docs_consistency.py` binds its repository root at import; the real checker is
run beside it as a positive control, which is what shows the adapter is connected
to it.

---

## 5. Everything executed here

**Recorded at `8a697aa7e`.** The table below is the run at the identity in the
header, at which the claim set conjoined to `CONTRADICTED` with 42 open
obligations. It is history; §9 records the run at `2d31a23fb`.

All in `openssl-rs-court-tools:1`; the container's 8 GiB cap was already applied.

| command | result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --all-targets -- -D warnings` | exit 0 |
| `cargo test --lib -- --test-threads=4` | 2422 passed, 0 failed, 54 ignored, 135.08 s |
| `python3 forensics/tools/etp_claims.py validate` | 35 claims, 0 refusals, valid |
| `python3 forensics/tools/etp_claims.py conjoin` | verdict `CONTRADICTED`, 33 blocked, 42 open obligations |
| `python3 courts/phase18/interop/check_receipts.py --summary` | 14 receipts, 2 manifests, 0 problems |
| `python3 forensics/tools/instrument_qualify.py check` | register ok, 9 executable controls PASS, 2 RECORDED, 0 NOT_RUN |
| `python3 forensics/tools/docs_consistency.py` | 20 claims agree; one documented exemption |
| `python3 forensics/tools/docs_consistency.py --self-test` | `self-test: skipped: the ledger has an empty side` (exit 0; recorded as `NOT_RUN`, not a pass) |
| `python3 forensics/tools/tests/test_analyse_bench_api.py` | 34 tests, OK |
| `python3 forensics/tools/tests/test_etp_claims.py` | exit 0 |
| `python3 forensics/tools/release_gate.py --self-test` | 8/8 cases |
| `python3 forensics/tools/release_gate.py --package /tmp/pkg-etp7` | exit 1, four claim refusals (verbatim above) |
| the eight `assurance` steps | extracted from the parsed YAML and replayed in order; all exit 0 (the documentation self-test reports `skipped`, recorded as `NOT_RUN`) |
| `etp6_package.py` from HEAD and the package's `verify.sh` | package built; `RESULT: PASS (5/5 required steps PASS)` |
| YAML parse of `.github/workflows/ci.yml` | parsed; jobs `lint`, `adversarial`, `assurance`, `static`, `courts` |

**Not executed:** GitHub Actions itself. The workflow was parsed as YAML and all
eight `assurance` step bodies (including both inline heredocs) were extracted
from the parsed document and replayed in the court in order; all exited 0. No
GitHub runner ran the workflow, so scheduling, `${RUNNER_TEMP}`, artefact
download and the runner's toolchain are only syntactically verified. The
`assurance` job's commands use only the Python standard library and the
repository; no runner-specific package is assumed.

---

## 6. Gaps, stated plainly

1. **Not automatic on a tag.** There is no release script and no tag-triggered
   `cargo publish` path, so `release_gate.py` is a mandatory manual step. A
   maintainer can still publish without it. Closing this needs a tag-triggered
   workflow in the qualified court image, the ETP-6 package as an uploaded
   artefact, and protection on the tag. That is infrastructure work and is not
   claimed here.
2. **The instrument register cannot run on a bare runner.** Its register is
   venue-bound and every version probe executes; `instrument_qualify.py validate`
   and `check` both fail closed with `IQ_VERSION_COMMAND` when, for example,
   `binsec` is absent (observed by stripping `PATH`). The FAST CI job therefore
   runs the claim, receipt, documentation and analyser gates, not the instrument
   gate; the instrument gate runs in the release gate and the court. Provisioning
   the tools image for CI is a named infrastructure gap.
3. **Only one section 6 structural guard is a FAST gate.** The lint-attribute
   assertion plus clippy cover `SAFETY:`-per-unsafe-op and lint weakening. There
   is no FAST-frequency standalone tool for the allocator seam, `#[repr(C)]`
   layouts or exported symbols; those remain seal-tier (`ownership_audit.py`,
   `prototype_court.py`, the Phase-2 ABI courts). This is an absence of tooling,
   not a claim that the properties are checked.
4. **The ETP-6 frozen manifest drifts with this change.** The package built from
   HEAD passes. Building a provisional package that includes the ETP-7 files
   refuses, as it should:

   ```
   HARD  docs/CI.md: digest mismatch: 402cb682… != 32f25392…
   HARD  docs/ETP-TODO.md: digest mismatch: df4cc9fa… != e8ae1bfc…
   HARD  docs/RELEASE_GATES.md: digest mismatch: 2ffca98d… != 71d8060f…
   HARD  forensics/tools/release_gate.py: input is present but absent from the frozen manifest
   no archive written; review the drift, then --refreeze.
   ```

   The ETP-6 manifest must be refrozen at its next seal, and the release gate's
   package item is `RG_PACKAGE_MISSING` until a package is rebuilt and supplied.
   Refreezing is an ETP-6 act, not an ETP-7 edit.
5. **The documentation self-test does not currently run.** It reports
   `skipped: the ledger has an empty side` at this candidate. It is recorded as
   `NOT_RUN`; the CI step warns and continues, and the main documentation
   consistency check still runs and passes.
6. **The gate decides machinery, not truth.** A PASS would not establish that a
   claim is true, that an instrument result is representative, or that the
   package was produced independently. The claim algebra checks typing and law;
   the gate checks that the named machinery accepted this candidate.
7. **The gate does not require the claim set's frozen source identity to equal
   the candidate.** The committed claims are bound to `S = 9372bb28b` and record
   their own `identity` binding; a later candidate is a §22 identity question,
   not a fact this gate silently promotes. The gate prints the claim source
   identity in its recorded output so the mismatch is visible. Enforcing a
   refreeze at the release candidate is §22/ETP-T15 work and is not claimed here.

---

## 7. Obligations

| kind | item |
|---|---|
| discharged (mechanical) | the six release items now have one fail-closed decision; the FAST Python gates run on every push; the tier thread count is named; the gate refuses each claimed failure class, proven per class |
| retained | ETP-T15 reconciles the four contradicted claims; ETP-6 refreezes the package manifest; the release gate stays manual until a tag workflow exists; the candidate-versus-`S` identity question remains §22 work |
| newly introduced | a requirement that a release supply a built ETP-6 package, and that the instrument gate run in the qualified venue. Both fail closed; neither is evidence that the release is safe |
| known absent | FAST-frequency allocator-seam, `#[repr(C)]` and export-symbol guards; instrument gate on a GitHub runner |

---

## 8. Publication note

The workflow change is tracked as `forensics/etp7/ci-assurance-job.patch` rather
than applied in `.github/workflows/ci.yml`. The credential used to push this
branch is an OAuth app without the `workflow` scope, and GitHub rejects a workflow
update from it (`refusing to allow an OAuth App to create or update workflow
.github/workflows/ci.yml without workflow scope`). The patch applies the
`assurance` job and the two edits described in §3.

Until it is applied, the Python gates run only when invoked by hand and the
release gate stays a manual step, which is the gap recorded in §7. Applying the
patch requires a credential with `workflow` scope; the resulting workflow must
then be executed and its first run recorded here.

---

## 9. Re-run at `2d31a23fb` (2026-11-23, A0-F06)

**Why this section exists.** §3 and §5 are the run at `8a697aa7e` and are
superseded; this section records the same gate at the repaired candidate, with
the claim-set bytes it read, so that a reader does not have to choose between two
undated transcripts. Nothing in §3 or §5 is edited.

**Candidate:** branch `staging`, HEAD `2d31a23fb25f52ab4c443212d34cd05ded715185`,
2026-11-23. The run is taken on the working tree that carries the A0 repairs
(`F01`, `F06`, `F10`); the gate counts the uncommitted paths itself. Those twelve
paths are:

```
?? evidence/a0/REPAIRS-2.md
 M docs/ETP-TODO.md
 M docs/EVIDENCE-AUDIT.md
 M docs/RELEASE_GATES.md
 M evidence/closure-curl-049.json
 M evidence/etp7/RECEIPT.md
 M evidence/etp-t6/CLAIM-MATRIX.json
 M forensics/STATUS.md
 M forensics/tools/closure_discipline.py
 M forensics/tools/consumer_closure.py
 M forensics/tools/render_status.py
 M forensics/tools/tests/test_closure_discipline.py
```

`evidence/etp/claims.json` is **not** among them: the claim document is the same
bytes ETP-T15 left, and this repair changes no claim. The receipt itself is one
of the twelve, at the state that precedes this section (the section was appended
after the run). The `validate` output below names the document by its court
path, because that is the path the command printed.

**The claim-set bytes each transcript read.** This is the binding §3 lacked:

| run | `evidence/etp/claims.json` sha256 |
|---|---|
| §3, at `8a697aa7e` | `65d8105b744c80ae01e76af8bf3370c478ab116c7fc9b0f16f63eea5d5c579de` |
| §9, at `2d31a23fb` | `2968ffd6976f19bd701c58636b51cceed192e42c928dd2116217449a7b85a1bb` |

The digests differ because ETP-T15 rewrote the claim set between the two runs
(four verdicts reclassified, five obligations discharged). The claim source
identity the gate prints is unchanged in both runs (`S = 9372bb28b`): the claims
remain bound to the frozen source, and the repaired candidate is a later tree,
which is the identity question `AGENTS.md` §22 keeps separate.

**Command, verbatim:**

```
python3 forensics/tools/release_gate.py
```

**Output, verbatim (exit 1):**

```
release-gate: candidate 2d31a23fb25f52ab4c443212d34cd05ded715185; 12 uncommitted path(s) (tracked or untracked; ignored paths excluded)
release-gate: identity triage IDENTITY-TRIAGE.json: 21 DERIVED, 13 DECLARED, 79 HISTORICAL, 118 UNCERTIFIABLE; 118 artefact(s) cannot support a claim
release-gate: claim ETP0-CLM-004: verdict SUPERSEDED (recorded, not a release block)
release-gate: claim ETP0-CLM-005: verdict SUPERSEDED (recorded, not a release block)
release-gate: claim ETP0-CLM-032: verdict SUPERSEDED (recorded, not a release block)
release-gate: claim ETP0-CLM-033: verdict SUPERSEDED (recorded, not a release block)
release-gate: claim conjunction: SUPERSEDED
release-gate: claim source identity: 9372bb28b2fbe2f71cf2aa2ab501414d45e87d42
release-gate: receipt  RECEIPT-o10.json             live
release-gate: receipt  RECEIPT-o12.json             live
release-gate: receipt  RECEIPT-o2.json              live
release-gate: receipt  RECEIPT-o3.json              live
release-gate: receipt  RECEIPT-o4.json              live
release-gate: receipt  RECEIPT-o5.json              live
release-gate: receipt  RECEIPT-o6.json              live
release-gate: receipt  RECEIPT-o7-AA.json           live
release-gate: receipt  RECEIPT-o7-AB.json           live
release-gate: receipt  RECEIPT-o7-BA.json           live
release-gate: receipt  RECEIPT-o7-BB.json           live
release-gate: receipt  RECEIPT-o7.json              live
release-gate: receipt  RECEIPT-o8.json              live
release-gate: receipt  RECEIPT-o9.json              live
release-gate: manifest MANIFEST-o11-A.json          log=present
release-gate: manifest MANIFEST-o11-B.json          log=present
release-gate: receipts=14 manifests=2 problems=0
release-gate: QUALIFICATION ok: every requested control passed and matched the register
release-gate: [docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-006/artifacts/phase18/COURTS.json: claim ETP0-CLM-006 (ESTABLISHED) requires artifacts/phase18/COURTS.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 23 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-007/forensics/phase18-obligations.json: claim ETP0-CLM-007 (ESTABLISHED) requires forensics/phase18-obligations.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 22 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-011/courts/phase18/timing/RECEIPT-timing-unified.json: claim ETP0-CLM-011 (PARTIAL) requires courts/phase18/timing/RECEIPT-timing-unified.json, which is a record of introduced-at-single-commit at 99ab0d04254b3588c9786f63ebf8a2af59d64109 and may not be cited as current evidence
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-011/courts/phase18/timing/RECEIPT-dudect-modes.json: claim ETP0-CLM-011 (PARTIAL) requires courts/phase18/timing/RECEIPT-dudect-modes.json, which is a record of introduced-at-single-commit at 4e4bc55a4c0cb9bf8b4678b469e2814061c88a8e and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-015/courts/phase18/interop/MANIFEST.json: claim ETP0-CLM-015 (PARTIAL) requires courts/phase18/interop/MANIFEST.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 2 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-015/courts/phase18/interop/RECEIPT-o2.json: claim ETP0-CLM-015 (PARTIAL) requires courts/phase18/interop/RECEIPT-o2.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 2 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-016/courts/phase18/interop/RECEIPT-o3.json: claim ETP0-CLM-016 (PARTIAL) requires courts/phase18/interop/RECEIPT-o3.json, which is a record of introduced-at-single-commit at 5c5788aa876646fcb7a51d43ceb46237af30cbd4 and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-017/courts/phase18/interop/RECEIPT-o4.json: claim ETP0-CLM-017 (PARTIAL) requires courts/phase18/interop/RECEIPT-o4.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 2 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-018/courts/phase18/interop/RECEIPT-o5.json: claim ETP0-CLM-018 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o5.json, which is a record of introduced-at-single-commit at 066b350e3a470d169ad4c7cc09b58bb6e1c2ffaa and may not be cited as current evidence
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-019/courts/phase18/interop/RECEIPT-o6.json: claim ETP0-CLM-019 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o6.json, which is a record of introduced-at-single-commit at dd0bee3a7e4177e56168b0720339958aed6239b6 and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-020/courts/phase18/interop/RECEIPT-o7.json: claim ETP0-CLM-020 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o7.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 3 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-020/courts/phase18/interop/RECEIPT-o7-AA.json: claim ETP0-CLM-020 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o7-AA.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 3 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-020/courts/phase18/interop/RECEIPT-o7-AB.json: claim ETP0-CLM-020 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o7-AB.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 3 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-020/courts/phase18/interop/RECEIPT-o7-BA.json: claim ETP0-CLM-020 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o7-BA.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 4 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-020/courts/phase18/interop/RECEIPT-o7-BB.json: claim ETP0-CLM-020 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o7-BB.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 2 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-021/courts/phase18/interop/RECEIPT-o7.json: claim ETP0-CLM-021 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o7.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 3 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-022/courts/phase18/interop/RECEIPT-o8.json: claim ETP0-CLM-022 (PARTIAL) requires courts/phase18/interop/RECEIPT-o8.json, which is a record of introduced-at-single-commit at 4da8b738a2167a9c56baafca153e98ba30357500 and may not be cited as current evidence
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-023/courts/phase18/interop/RECEIPT-o9.json: claim ETP0-CLM-023 (PARTIAL) requires courts/phase18/interop/RECEIPT-o9.json, which is a record of introduced-at-single-commit at d5c4e9c500a754699817f764c2d4dd449bd4cbd0 and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-023/courts/phase18/interop/MANIFEST-o11-A.json: claim ETP0-CLM-023 (PARTIAL) requires courts/phase18/interop/MANIFEST-o11-A.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 4 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-023/courts/phase18/interop/MANIFEST-o11-B.json: claim ETP0-CLM-023 (PARTIAL) requires courts/phase18/interop/MANIFEST-o11-B.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 4 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-024/courts/phase18/interop/RECEIPT-o10.json: claim ETP0-CLM-024 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o10.json, which is a record of introduced-at-single-commit at 63fca4cc4e5bff3342c8c5d3add5672090d92a26 and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-025/courts/phase18/interop/MANIFEST-o11-A.json: claim ETP0-CLM-025 (ESTABLISHED) requires courts/phase18/interop/MANIFEST-o11-A.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 4 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-025/courts/phase18/interop/MANIFEST-o11-B.json: claim ETP0-CLM-025 (ESTABLISHED) requires courts/phase18/interop/MANIFEST-o11-B.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 4 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-026/courts/phase18/interop/RECEIPT-o12.json: claim ETP0-CLM-026 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o12.json, which is a record of introduced-at-single-commit at 1bb9f25936b8d1fc0fa0ee71bb7c70da6aab7734 and may not be cited as current evidence
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-027/courts/phase18/interop/RECEIPT-o12.json: claim ETP0-CLM-027 (ESTABLISHED) requires courts/phase18/interop/RECEIPT-o12.json, which is a record of introduced-at-single-commit at 1bb9f25936b8d1fc0fa0ee71bb7c70da6aab7734 and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-028/forensics/downstream/runtime-functional-atlas.json: claim ETP0-CLM-028 (PARTIAL) requires forensics/downstream/runtime-functional-atlas.json, which has no certifiable identity: U1 multi-commit-no-declaration -- the artefact was changed in 72 commits and names no tree, so no single moment explains its current bytes
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-029/forensics/memory-safety/campaign/safe-c33/CLOSURE.md: claim ETP0-CLM-029 (ESTABLISHED) requires forensics/memory-safety/campaign/safe-c33/CLOSURE.md, which is a record of declared-prose-frozen-at at 67ae7f8e9f3381ce0dac1dae9a23bfa3937bec34 and may not be cited as current evidence
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-034/artifacts/phase25/summary.json: claim ETP0-CLM-034 (ESTABLISHED) requires artifacts/phase25/summary.json, which has no certifiable identity: U2 candidate-name-only -- the only declared identity is the candidate name 'openssl-rs 0.0.27 (reconstructing openssl-3.6.4-production)', and the repository binds that name to more than one tree, so it does not determine a commit
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-035/artifacts/phase2/install/lib/libcrypto.so.3: claim ETP0-CLM-035 (PARTIAL) requires artifacts/phase2/install/lib/libcrypto.so.3, which has no certifiable identity: U6 build-output-no-identity -- a build output carries an embedded binary, not the tree that produced it
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-035/artifacts/phase2/install/lib/libssl.so.3: claim ETP0-CLM-035 (PARTIAL) requires artifacts/phase2/install/lib/libssl.so.3, which has no certifiable identity: U6 build-output-no-identity -- a build output carries an embedded binary, not the tree that produced it
REFUSED RG_PACKAGE_MISSING -: no --package was supplied; the ETP-6 external-package verifier is a required release item, so an absent package is a refusal
release-gate: REFUSED (31 item(s))
```

**The claim algebra beside the gate.** `python3 forensics/tools/etp_claims.py
validate` prints
`{"claims":35,"document":"/work/evidence/etp/claims.json","refusal_count":0,"refusals":[],"refusals_by_rule":{},"valid":true}`
and exits 0. `python3 forensics/tools/etp_claims.py conjoin` returns a document
whose scalars and list lengths are `verdict: SUPERSEDED`, `blocked_by`: 33,
`obligations`: 37, `members`: 35, `weakest`: 4. The full document — every member
and every obligation — is reproduced by that command and is not transcribed
here; this paragraph is a summary, not a transcript.

**What changed between the two runs, and what did not.**

| item | §3, `8a697aa7e` | §9, `2d31a23fb` |
|---|---|---|
| claim conjunction | `CONTRADICTED` | `SUPERSEDED` |
| blocked members | 33 | 33 |
| open obligations | 42 | 37 |
| claim refusals | 4 `RG_CLAIM_CONTRADICTED` | 19 `RG_CLAIM_UNCERTIFIABLE_EVIDENCE` and 11 `RG_CLAIM_HISTORICAL_EVIDENCE` |
| package item | `RG_PACKAGE_MISSING` (no `--package`) | `RG_PACKAGE_MISSING` (no `--package`) |
| refused items | 5 | 31 |
| interop receipts | 14 receipts, 2 manifests, 0 problems | 14 receipts, 2 manifests, 0 problems |
| instrument register | ok, every requested control passed | ok, every requested control passed |
| documentation | 20 hand-written claims agree | 20 hand-written claims agree |

The conjunction moved off `CONTRADICTED` because ETP-T15 reclassified the four
contradicted claims (`-004`, `-005` and `-032` to `SUPERSEDED`, `-030` to
`RISK_ACCEPTED`) and discharged five obligations. It did not move because this
repair resolved anything, and `SUPERSEDED` is not a pass. The gate refuses
**more** items at this candidate than it did at `8a697aa7e` — thirty-one against
five — because the identity-triage item did not exist when §3 was recorded and it
now refuses claims whose evidence has no certifiable identity. The release
decision is the last line: exit 1, 31 refusals.

**Not run here:** GitHub Actions (unchanged from §6), `cargo` of any kind (no
`src/` change), and the ETP-6 package item (no package was built for this
candidate, so the item is `RG_PACKAGE_MISSING` rather than a package result). The
ETP-T10 evidence has **not** been re-emitted at this candidate, so the
`consumer-curl` step of `verify.py` reports the repaired closure receipt as a
digest mismatch against the identity ETP-T10 audited; that report is true, and
its remedy is
`python3 forensics/tools/closure_discipline.py emit --commit <commit containing the repair>`,
which cannot run before the repair is committed. Record:
`evidence/a0/REPAIRS-2.md`.
