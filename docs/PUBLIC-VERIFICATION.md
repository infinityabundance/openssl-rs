# Public verification interface — ETP-T12

**Status:** the interface, its controls and its clean-checkout demonstration
exist. The first clean-checkout run is **red**: 8 of 19 steps pass, 9 fail, 2 are
`NOT_RUN`, and `verify all` exits 1. The run is recorded verbatim in
`evidence/etp-t12/RECEIPT.md`; the machine-readable document is
`evidence/etp-t12/RUN.json`.

**Entry point:** `forensics/tools/verify.py` (Python 3.11 standard library only).
**Controls:** `forensics/tools/tests/test_verify.py` (37 tests, `unittest`).
**Item:** ETP-T12 of `docs/ETP-TODO.md`.

Nothing in this document is a claim that a red step is a defect. Each verdict is
the delegated tool's, at the candidate it names, bound to the tool and evidence
digests in the run document.

---

## 1. What the interface is

One dispatcher over verification tools that already exist in this repository.
Every subcommand invokes one of those tools; the interface decides nothing about
the subject matter. It adds exactly four things a set of scripts does not have:

1. a single entry point with a fixed exit contract;
2. one status vocabulary — `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN` — with a
   fail-closed rule for each;
3. a binding of each verdict to the evidence identity and the tool digest it was
   produced with;
4. an explicit declaration of what each step needs, what it establishes, what it
   does not, and which private paths its tool may read.

Adding a new verification question means adding a delegate and a declaration, not
a second interface.

## 2. Invocation and exit contract

```
python3 forensics/tools/verify.py <subcommand> [--json] [--network] [--explain] [--list]
python3 forensics/tools/verify.py all [--json]
```

| exit | meaning |
|---|---|
| `0` | every selected required step is `PASS` |
| `1` | at least one selected step is not `PASS`; for a single-step request, that step is not `PASS` |
| `2` | the invocation was refused before any step ran: unknown subcommand, unreadable checkout, malformed selection |

`NOT_RUN` is never a pass and never exits 0. A single optional step is gated on
itself, so `verify authority` cannot report `NOT_RUN` and exit 0.

`--json` (on a step run or on `all`; `--list` and `--explain` print their
text regardless, because they are discovery commands rather than step runs)
emits one sorted, timestamp-free document: per step `name`, `status`,
`reason` (empty when `PASS` is explained by `pass_reason`; a named cause
otherwise), `evidence_identity` (path and SHA-256, or `absent`), `tool_digest`,
`prerequisites` (each requirement, whether it was available and why),
`private_state_declared` and `private_state_present`, and every command with its
exit status and the normalised tail of its output. The document also carries an
`environment` block with the live readings the run observed (`MemAvailable`, the
derived court cap, the court) and marks it as an environment input; the block is
recorded, not compared, and the byte-identity claim is about the rest of the
record. Two runs over the same checkout with the same inputs are byte-identical
in everything except that declared block and the `private_state` entry counts,
which are live readings of the working tree's untracked or ignored entries and
not of the checkout (A25 D5).

`--list` names every subcommand and whether it is in `all`. `--explain [name]`
prints the prerequisites, establishment and non-claim of one step or all of them,
so the interface documents itself.

## 3. Subcommands

The first eleven are the names the ETP-T12 queue fixes. `all` runs every name in
the table except `authority`, in the listed order. `consumer-*` is expanded for
the three families `evidence/etp-t10/EXCLUSIONS.json` records.

| subcommand | needs | delegates to | establishes | does not establish |
|---|---|---|---|---|
| `manifest` | `git` | `forensics/tools/etp6_package.py --commit HEAD` | every input the tracked ETP-6 package manifest names is present at this commit with the recorded SHA-256 | that a package was built, archived or published; any property of its contents |
| `rebuild` | `bash`, `rustc`, `cargo`, the court, **24 GiB available** | `forensics/tools/build_reproducibility.sh` | the `.a` and the linked DSO are byte-identical across two independently produced release builds | that the build is correct; that another host or toolchain reproduces it |
| `proofs` | `python3` | `forensics/etp5_crypto/make_vectors.py --check`, `driver.py --self-test` | the independent reference regenerates every tracked vector byte-for-byte and its difference classifier passes its own controls | that the reference agrees with the candidate or the authority; that the reference is correct beyond its vectors |
| `differential` | `bash`, `rustc`, `cargo`, the court, **24 GiB**, the authority prefix | `forensics/etp5_crypto/run_etp5.sh` | bounded differential agreement across the reference, the candidate and the pinned authority on the sampled populations | algorithm correctness in general; constant-time behaviour; memory safety; refinement |
| `instruments` | `python3` | `forensics/tools/instrument_qualify.py check` | each instrument's identity matches the register and its executable control fired in the venue that ran it | that any instrument is adequate for untested inputs; an absent external tool is `NOT_RUN`, not a sensitivity result |
| `controls` | `python3` | `python3 -m unittest discover -s forensics/tools/tests` | the verification tools' negative controls, determinism checks and refusal paths pass at this candidate | that a control is complete for its defect class; court-level instrument controls |
| `receipts` | `python3` | `courts/phase18/interop/check_receipts.py` | rules R1–R5 over the committed interop receipts and manifests: parseability, withdrawal naming, cell-result integrity, log digest, derived counts | that a receipt's measurements are true; a manifest that points into `court/` fails R4 in a clean checkout by design |
| `consumer-<family>` | `python3`, `git`, the family's recorded receipt; declared private reads | `forensics/tools/closure_discipline.py audit --receipt …` | the five-requirement exclusion bar and opaque-operation scope over one recorded closure receipt, bound to the receipt digest ETP-T10 audited | that an admitted exclusion is sound; an absent private inventory makes every dependent row fail |
| `claims` | `python3`, `git` | `forensics/tools/etp_claims.py validate` | the committed claim set passes the schema, the cross-field laws and the Git-bound digest re-derivation | that any claim is true; a valid set may contain `CONTRADICTED` or `NOT_ESTABLISHED` members |
| `freshness` | `python3`, `git` | `forensics/tools/freshness.py check` | every artefact is unaffected, history, invalidated or explicitly unresolved with a named reason, and no undeclared carry-forward remains | that `UNAFFECTED` is a fresh measurement; the identity triage bounds what the verdict means |
| `independence` | `python3`, `git` | `forensics/tools/independence.py check` | assignments claiming independence do not share a party where the class forbids it, with dissent recorded | that an external party exists; unknown distinctness is reported, never assumed |
| `closure` | `python3`, `git` | `forensics/tools/closure_discipline.py check` | the five-requirement bar over the recorded exclusion rows, opaque scope, and the aggregate refusal rule | that an admitted exclusion is sound, only that its argument is recorded and checkable |
| `scheduling` | `python3`, `git` | `forensics/tools/scheduling.py report` | the minimum tier each recorded change set needs and which required evidence is satisfied, `NOT_RUN`, `FAILED`, `REFUSED` or `BLOCKED` | that the required checks were run; a cache hit is evidence bound to its identity, not a fresh measurement |
| `traceability` | `python3`, `git` | `forensics/tools/traceability.py validate` | the typed requirements graph validates and every declared orphan is reproduced | population completeness; an orphan reason is an argument, not a proof |
| `hazards` | `python3`, `git` | `forensics/tools/hazard_register.py validate` | the hazard register and the traceability graph describe the same hazards, barriers and release claims | that a barrier works; barriers are classified by their recorded evidence |
| `binary` | `python3` | `forensics/tools/binary_assurance.py check` | every asserted binary claim names an artefact at its own target, profile and TCB | source-to-binary correspondence; an unbound claim is recorded, never promoted |
| `docs` | `python3` | `forensics/tools/docs_consistency.py` | the documents' derived figures agree with the artefacts they cite | that prose is complete, or that an exempt figure is correct |
| `authority` | `python3`, **the network** | `forensics/tools/authority_acquire.py --all --verify-only` | the local authority archives are the ones the registry admits, by published digest | that an upstream release is trustworthy; **not part of `all`** because it needs the network |
| `all` | the union | every step above except `authority` | the conjunction of the steps it runs, with the non-passing ones named | anything a step does not establish |
| `--list` | `python3` | — | the subcommand set and its role in `all` | — |

`consumer-<family>` families are `curl`, `ssh` and `sshd`, the three
`evidence/etp-t10/EXCLUSIONS.json` records. The guard re-reads that record and
requires the receipt path and its SHA-256 to match what ETP-T10 audited; a drift
is `FAIL` with both digests named, and a missing record is `FAIL`, not a skip.

The additional subcommands (`differential`, `traceability`, `hazards`, `binary`,
`docs`, `authority`) exist so that every tool this interface was asked to
integrate has its own named step instead of being folded into an unrelated one.
They are additions to the queue's list, not substitutes for it.

## 4. Prerequisites and how their absence is handled

| prerequisite | check | absence |
|---|---|---|
| `python3` | the interpreter running the interface | the interface cannot start |
| `git` | `shutil.which` | the step is `NOT_RUN` naming the missing program |
| `bash`, `rustc`, `cargo`, `cc` | `shutil.which` | `NOT_RUN` |
| the court | `/.dockerenv` | `NOT_RUN`, naming `docker/openssl-rs-court.sh` |
| 24 GiB available | `MemAvailable` in `/proc/meminfo` | `NOT_RUN` with the AGENTS.md §6.1 floor; **no build is started**. The observed value is recorded in the document's `environment` block (`mem_available_gib`, `mem_available_bytes`) and the prerequisite records the floor decision, not the magnitude |
| the authority prefix | `forensics/authorities/prefix/…/libcrypto.so.3` | `NOT_RUN`, naming the gitignored path |
| the network | the `--network` declaration | `NOT_RUN`; `--network` is a declaration, not a probe |
| the delegate itself | a file at the declared path | `NOT_RUN`, naming the tool |

No prerequisite is satisfied by the working tree's private state: a private path
is either declared by the step and reported as present, or absent and reported as
absent. `court/` is reported precisely — its tracked files as `tracked_files`,
its untracked or ignored entries as `private_entries` — so the 278 tracked files
present in a clean checkout are not presented as private content, and a private
census is not presented as checkout content.

No step needs a private key. Signing, publication and release authority are
outside this interface; `release_gate.py` remains the separate release decision.

## 5. Evidence identity, tool digest and status rules

* `evidence_identity` is the SHA-256 of each evidence file the verdict is about.
  A directory is digested over its **Git-tracked** files only, so the identity is
  the checkout's, not a filesystem coincidence.
* `tool_digest` is the SHA-256 of each delegate (or of the tracked test tree for
  `controls`).
* exit 0 → `PASS`; a documented "could not run" code → `NOT_RUN` with its reason;
  a documented resource-bound code → `BLOCKED`; a timeout → `BLOCKED`; any other
  non-zero exit → `FAIL`. A command that cannot be started is `FAIL`, not
  `NOT_RUN`, because the delegate was present and the failure is not an absent
  prerequisite.
* For a multi-command step the worst status wins: `FAIL` > `BLOCKED` > `NOT_RUN` >
  `PASS`.

## 6. Determinism

No timestamp is written. Every list is sorted on a documented key. `tmpdir` is
recorded as `<tmp>`; the checkout path, temporary paths and elapsed times are
normalised out of captured output before it enters the document. Two `--json`
runs of `all` over the same checkout were compared with `cmp` and are
byte-identical (receipt §6).

## 7. The clean-checkout demonstration

A fresh `git clone --no-hardlinks` of the repository was made inside the court's
bind mount, its `origin` removed, and the two new scripts copied in as untracked
additions. The checkout has no `court/tmp/`, no `target/`, no authority prefix and
no authority download. `git status --porcelain --ignored=matching` reports two
untracked deliverable files and no ignored entry. `HOME` and `TMPDIR` were
created empty for the run.

Observed: `verify all` exited **1**; 8 steps `PASS`, 9 `FAIL`, 2 `NOT_RUN`
(`rebuild`, `differential`), and the output named all 11 non-passing steps.
`RUN.json` and the verbatim text are in `evidence/etp-t12/`. The two `NOT_RUN`
steps are the §6.1 memory floor, not a result; the nine `FAIL` steps are the
delegates' refusals at this candidate.

The development tree was also run for the private-state comparison: with the
`court/freeze-b85` census present, `consumer-ssh` reports 337 of 374 rows failing
and `consumer-sshd` 290 of 327; without it, 374 of 374 and 327 of 327. The
interface reports the difference and does not present the private-state result as
the clean one.

## 8. Controls

The interface's own controls are `forensics/tools/tests/test_verify.py` (37
tests): missing tool → `NOT_RUN`; non-zero → `FAIL`; timeout → `BLOCKED`; offline
network step → `NOT_RUN` with the reason; absent and drifted receipt → `FAIL`;
private path reported when present; `all` non-zero and every non-passing step
named; two `--json` runs byte-identical; unknown subcommand → exit 2. Six of them
run the real command line in a throwaway tree of stub delegates, so the exit
contract and the serialisation are exercised end to end.

The interface's controls are not the instruments' controls. Whether an
independent instrument is sensitive to the defect it claims to detect is the
`instruments` step's question, delegated to `instrument_qualify.py`.

## 9. What this interface cannot verify

* It cannot turn a red delegate green. The red result is the deliverable's value.
* It cannot establish any claim's truth; `binary` passes with four unbound claims
  and `claims` passes with `CONTRADICTED` members.
* It cannot produce a reproducibility or three-way differential result where the
  venue cannot run one; those steps are `NOT_RUN`, not evidence.
* It cannot create independence, and it does not adjudicate a failed assignment.
* It cannot prove that a delegate reads no private state. The declarations are
  the audit surface; an undeclared read is a defect in the delegate, and this
  report would not detect it.
* It cannot verify its own interpreter, the court image or the kernel. The tool
  digests bind verdicts to scripts, not to the runtime.
* It is not a sandbox: clearing proxy variables offline is defence against an
  accidental network attempt, not an isolation boundary.
* It is checkout-scoped. The ETP-6 reproduction package keeps its own
  `verify.sh`/`etp6_verify.py`; `verify.py` is not added to that package's
  selection in this batch, so an external package does not yet dispatch these
  subcommands.

## 10. Non-claims

The interface is not a security boundary, not a certification and not a release
gate. A green `verify all` would establish only that the delegated checks passed
at that candidate with the recorded tool and evidence digests. The queued
`release_gate.py` remains the separate, stricter decision; this interface does
not replace it and does not weaken it.
