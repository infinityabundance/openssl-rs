# ETP-7 — continuous enforcement in CI and release tooling

**Candidate:** branch `staging`, HEAD `8a697aa7ea993e4e25ef38351b51d6b24148606c`,
2026-11-22. The gate was run against this tree before the ETP-7 files were
committed; the six uncommitted paths it reports are the ETP-7 edits to
`.github/workflows/ci.yml`, `docs/{CI,RELEASE_GATES,ETP-TODO}.md`, the new
`forensics/tools/release_gate.py` and the new `evidence/etp7/`. No `src/` file,
campaign raw data or another item's evidence was changed.

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
