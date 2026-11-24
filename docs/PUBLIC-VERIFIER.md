# The public verifier contract

**Status:** declared and mechanically enforced at `a9bcb5480`. This document
defines what an outsider may rely on when driving `forensics/tools/verify.py`;
`evidence/a25/SURFACE.json` (schema `openssl-rs/public-surface/1`) is the
machine-readable declaration of the same contract, and
`forensics/tools/public_surface.py verify` is the check that the declaration and
the executable have not drifted apart.

**Normative for:** the command set, the invocation forms, the exit-code
contract, the JSON document's schema and top-level fields, the stability levels,
the private-state rule and the determinism rule.

**Not normative for:** what any individual check means. Each command's subject
matter, prerequisites, establishment and non-claim remain the per-command
register in `docs/PUBLIC-VERIFICATION.md`.

---

## 1. Two documents, and why

`docs/PUBLIC-VERIFICATION.md` is the **older descriptive document**. It was
written from the interface's behaviour at ETP-T12: nineteen step descriptions,
the status vocabulary, the clean-checkout run it observed, and what each step
does not establish. It is still the normative register for those per-step
statements, and it is where a reader goes to learn what `claims` or `scheduling`
is *about*.

This document is the **contract**. It exists because a description written from
behaviour cannot be the thing a caller programs against: the description is
long, it discusses nineteen different subjects, and no check compares its prose
with the program. So the shape of the interface — which words it accepts, which
numbers it returns, which fields it emits, which of those may change — is
declared separately, in a short form, and compared with the executable on every
run.

There are therefore two documents because they answer different questions:

| question | document |
|---|---|
| what does the `claims` step establish, and what does it not? | `docs/PUBLIC-VERIFICATION.md` |
| which commands exist, what do they accept, and what do their exit codes and JSON fields promise? | this document |

Where the two disagree about the interface's *shape*, this document governs and
the disagreement is a defect: the descriptive document was written before the
surface was declared, and its §2 and §3 still describe the interface as it
looked then. The known differences are recorded in
`evidence/a25/INVENTORY.json` and listed in §9 below.

Neither document is read by the drift check. The check reads the **executable**.
A document can therefore be wrong without the check noticing — which is why the
test suite compares this document's own claims about the contract with
`SURFACE.json`, and why the descriptive document's stale figures are corrected
rather than trusted.

## 2. Discovering the surface

Three commands, all offline, all needing nothing but a Python 3.11 interpreter:

```
python3 forensics/tools/verify.py --list          # what exists
python3 forensics/tools/verify.py --help          # what the arguments are
python3 forensics/tools/verify.py --explain NAME  # what one command claims
```

`--list` prints one tab-separated row per step command: `name`, `role`
(`required` or `optional`) and `in_all` (`in all` or `not in all`). Twenty step
commands are listed. It is the set `all` selects, plus `authority`, which is
optional and not selected by `all`.

`--help` prints the accepted arguments. `--explain` with no name prints every
step's block; `--explain NAME` prints one; `--explain all` prints every step's
block, because `all` selects all of them.

The declared command set is **twenty-three** entries: the twenty step commands,
`all`, and two discovery commands (`list`, `explain`). The discovery commands are
declared as commands because they are part of the public surface, but only the
twenty step commands are listed: `--list` describes what can be *run*, and the
discovery commands are how a caller finds that out.

| command | kind | selected by `all` | what it is for |
|---|---|---|---|
| `manifest` | step | yes | the frozen ETP-6 package manifest describes this commit |
| `rebuild` | step | yes | two independent release builds agree byte for byte |
| `proofs` | step | yes | the independent reference reproduces its published populations |
| `differential` | step | yes | reference, candidate and pinned authority agree on sampled populations |
| `instruments` | step | yes | the instrument register's identities and sensitivity controls |
| `controls` | step | yes | the verification tools' negative controls and refusal paths |
| `receipts` | step | yes | rules R1–R5 over the committed interoperability receipts |
| `claims` | step | yes | the committed claim set, its laws and its Git-bound digests |
| `freshness` | step | yes | every artefact's freshness verdict and the refusal rules |
| `independence` | step | yes | independence assignments, with dissent retained |
| `closure` | step | yes | the five-requirement exclusion bar and opaque scope |
| `scheduling` | step | yes | the minimum tier each recorded change set needs |
| `traceability` | step | yes | the typed traceability graph and its declared orphans |
| `hazards` | step | yes | the hazard register reconciled with the traceability graph |
| `binary` | step | yes | every asserted binary claim names its artefact, target and TCB |
| `docs` | step | yes | the documents' derived figures against the artefacts they cite |
| `authority` | step | **no** | the local authority archives against their published digests; needs the network |
| `consumer-curl` | step | yes | one consumer family's recorded closure receipt |
| `consumer-ssh` | step | yes | one consumer family's recorded closure receipt |
| `consumer-sshd` | step | yes | one consumer family's recorded closure receipt |
| `all` | aggregate | — | every step selected by `all`, in the listed order |
| `list` | discovery | — | the command set, by invocation `--list` |
| `explain` | discovery | — | the self-description, by invocation `--explain` |

Each command's prerequisites, delegate, establishment and non-claim are in
`docs/PUBLIC-VERIFICATION.md` and in `--explain`; this table fixes only the
names, kinds and selection.

### 2.1 Accepted forms and precedence

| form | what happens |
|---|---|
| `verify.py NAME` | run the step command `NAME`, or `all` |
| `verify.py --list [anything]` | print the listing, exit 0. `--list` takes precedence over `--explain` and over running a command |
| `verify.py --explain [NAME]` | print the declaration; `--explain` takes precedence over running a command |
| `verify.py` (no arguments) | **refused**, exit 2 |
| `verify.py list` | **refused**, exit 2 — `list` is a flag, not a subcommand |

`--json`, `--network` and `--tmp` are accepted by every form and have no effect
on `--list` or `--explain`. `--network` is a declaration that the network is
available, not a probe: a wrong declaration shows up as that step's own failure.

The last two rows are defects in the executable, not parts of the contract, and
they are queued in §9. The contract states them because a caller must not be
surprised by them; a future release may make `verify.py list` do what the help
text says it does, which is why this document calls it a defect rather than a
feature.

### 2.2 Arguments

| argument | takes a value | effect |
|---|---|---|
| `command` | yes (positional) | one declared command name, or `all` |
| `--json` | no | emit the machine-readable document instead of the text report; only for step commands and `all` |
| `--network` | no | declare that the network is available |
| `--explain` | no | print prerequisites, delegation, establishment and non-claims |
| `--list` | no | print the command set |
| `--tmp TMP` | yes | use `TMP` as the temporary root instead of a fresh directory |
| `--help` (`-h`) | no | print usage and exit 0 |

No other argument is accepted. An unknown argument, or an option missing its
value, is refused by the parser with exit 2.

## 3. The exit-code contract

| code | meaning | whole contract |
|---|---|---|
| `0` | every selected required step is `PASS`. A single requested step gates on itself, so an optional step cannot be requested and reported as a pass while the run exits 0 | `stable` |
| `1` | at least one selected step is **not** `PASS`: `FAIL`, `BLOCKED` or `NOT_RUN`. `NOT_RUN` is never a pass and never exits 0 | `stable` |
| `2` | the invocation was refused before any step ran: an unknown subcommand, a malformed argument list, or a surface that cannot be read | `stable` |

No other exit code is produced. In particular `verify` never returns the exit
status of a delegate: a delegate's non-zero status becomes that step's `FAIL`
and the run still exits 0 or 1 according to whether every selected required step
passed.

Each command declares which of these it can return and, for each, whether the
code has been **observed** by a declared probe or is **command-specific** —
meaning it is the command's own run status, which this contract does not
exercise because doing so would run builds and the whole test suite. The
declaration names the probe for every observed code; a code declared with
neither an observation nor a basis is a defect.

The observed probes are: `--list` → 0, `--help` → 0, `--explain` → 0,
`--explain all` → 0, `authority` (offline) → 1, an unknown subcommand → 2, a
malformed argument list → 2, and `--explain` of an unknown name → 2. All three
codes of the contract are therefore observed without running a step.

## 4. The JSON document

`--json` on a step command or on `all` emits one JSON object. The schema
identifier is **`openssl-rs/verify/1`**. The document's top-level fields are
exactly these twelve; a missing field and an extra field are both refusals:

| field | meaning |
|---|---|
| `schema` | `openssl-rs/verify/1` — the document schema |
| `interface` | `ETP-T12` — the interface identifier |
| `candidate` | the checkout the run observed: commit, tree, branch, tracked-change count, untracked-change count, tracked cleanliness |
| `root` | the checkout root the run read |
| `invocation` | what was asked for: the network declaration, the temporary root (normalised to `<tmp>`), the selected step names |
| `private_state` | per declared root: whether it exists, how many files Git tracks there, how many untracked or ignored entries it holds; and which roots are present |
| `environment` | the declared environment input: `MemAvailable`, the 24 GiB floor decision, the derived court cap and its source, the court identity — see §7 |
| `warnings` | non-fatal declaration problems observed before any step ran (for example, a recorded consumer receipt that is absent) |
| `steps` | one record per selected step: `name`, `title`, `required`, `status`, `reason`, `establishes`, `does_not`, `prerequisites`, `evidence_identity`, `tool_digest`, `reads_gitignored`, `private_state_declared`, `private_state_present`, `checks` |
| `counts` | `selected`, and `by_status` over `PASS`/`FAIL`/`BLOCKED`/`NOT_RUN` |
| `non_passing` | the names of the selected steps that are not `PASS`, in selection order |
| `status` | `PASS` only when every selected required step is `PASS`; otherwise `FAIL` |

`steps[].status` is one of the four statuses; `steps[].checks[]` carries each
executed command's selection `index`, `argv`, `cwd`, `exit`, `status`, `detail`
and the normalised tail of its output. Every list is sorted on a documented key
and no timestamp is written.

`--list` and `--explain` emit **no** JSON document: they print their text
regardless of `--json`. Their declared field set is empty, and a document
appearing where the contract says there is none is a refusal.

## 5. Stability levels

Every command declares one level. The level is a promise about the command's
*shape*, not about its verdicts.

| level | promise | removal |
|---|---|---|
| `stable` | the command name, its accepted arguments, its exit codes and its JSON fields will not change incompatibly within schema version 1. A change needs a new `schemaVersion` and a recorded migration | only by deprecation |
| `experimental` | may change or disappear without notice; do not program against it | any release |
| `deprecated` | still executable and still described; a `replacement` command is named; removed at the next schema version | next schema version |

A level is not an adjective. It must be supported: every level needs a `since`
token and at least one evidence path that exists at the declared candidate;
`stable` additionally needs the surface's declared support tests to be present
in the declared test file. A `stable` claim with no test that exercises it, an
evidence path that does not exist, or a `deprecated` command with no successor
is refused.

All twenty-three commands are `stable` at `a9bcb5480`. Nothing in this repository
is `experimental` or `deprecated` today; the levels exist so that a future change
has a truthful option besides silent breakage.

## 6. The private-state rule

The interface reads **no** private state. It resolves its repository root from
its own path, reads Git-tracked content, and reports the presence of the
gitignored roots it knows about without reading them.

Each command declares the gitignored roots its **delegate** may read. The check
compares that declaration with the executable's own `--explain` output in both
directions: a read the executable declares and the surface does not, and a read
the surface declares and the executable does not, are both refusals.

Presence is never evidence. The document reports which declared roots exist and
how many untracked or ignored entries each holds, so a reader can see that a
verdict was produced on a machine with a private census present — and can see
that the verdict is not thereby a clean-checkout result. The tracked-file count
is separate, because tracked files under a declared root are part of the
checkout and are not private content.

**Known gap (D4).** The three consumer commands declare
`artifacts/phase2/install` as private, but the interface's audited root set names
`artifacts/phase2/shell`, so the declared path is never counted and its presence
can never be reported. The rule above is what the interface is supposed to do;
the executable does not yet do it for that one path. It is queued, not hidden.

## 7. Determinism

Two runs of the same command over the same checkout produce the **same
deterministic record**:

* no timestamp, wall-clock reading, temporary path, elapsed time or checkout
  path is written into it; the temporary root is normalised to `<tmp>`;
* every list is sorted on a documented key;
* the declared `environment` block is an **input to the run**, not an output:
  it records the memory availability, floor decision, derived court cap and
  court identity the run saw. It is emitted so a verdict can name its venue, and
  it is excluded from the comparison. Its presence and shape are still required:
  a document that omits it, or claims a met floor with no reading, is refused.

Everything else is compared, field by field, across two runs. A difference is a
refusal that names the differing paths.

**Known gap (D5).** The top-level `private_state` entry counts are live `git
status` readings and are inside the compared record. Two runs over a checkout
are byte-identical only while the working tree is quiescent; an untracked entry
appearing between them changes the record. The rule that should hold — that
every live reading is declared as an input — is not yet implemented for that
block. It is queued, not hidden.

The listing is compared too: two `--list` runs must be byte-identical, because
the command set is the input to every other comparison.

## 8. The refusal table

The check is `python3 forensics/tools/public_surface.py verify`. It exits 0 and
prints `codes=PV_OK` when the declaration and the executable agree, 1 and the
refusal codes when they do not, and 2 for a usage error. Every code is stable;
each names the wrong conclusion it prevents.

| code | fires when | the wrong conclusion it prevents |
|---|---|---|
| `PV_REFUSED_COMMAND_UNDOCUMENTED` | the executable lists or explains a command the surface does not declare | "this is the whole interface" when a caller can invoke something undocumented |
| `PV_REFUSED_COMMAND_ABSENT` | a declared command is not executable, not listed, not explained, or its recognition probe fails | programming against a command that does not exist |
| `PV_REFUSED_EXIT_UNDEFINED` | an observed exit code has no declared meaning, a declared observation produced a different code, or a command declares a code the contract does not define | treating an unknown status as success or as a known error |
| `PV_REFUSED_EXIT_UNUSED` | the contract or a command declares a code that no probe observes and no command-specific basis covers | a documented exit code that cannot happen, or one that happens unobserved |
| `PV_REFUSED_HELP_DRIFT` | `--help` names an argument the surface does not declare, the surface declares an argument `--help` does not name, or `--explain`'s prerequisites or delegates differ from the declaration | a caller reading one interface while invoking another |
| `PV_REFUSED_JSON_FIELD` | the document lacks a declared field, carries an undeclared one, is not a document where one is declared, or is one where none is declared, or the listing's JSON behaviour changed | a consumer parsing a shape that is no longer emitted |
| `PV_REFUSED_UNSTABLE_OUTPUT` | two runs differ in the compared record, `--list` differs between runs, or the document fails to declare its environment input | a reproducibility claim over a record that moves |
| `PV_REFUSED_PRIVATE_STATE` | a command's declared private reads and the executable's own declaration disagree | a hidden dependency on state a clean checkout does not have |
| `PV_REFUSED_UNVERSIONED_SCHEMA` | the surface declares no `schemaVersion` | changing a declaration without any way to tell which declaration a consumer read |
| `PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT` | a `deprecated` command names no successor, names itself, names an undeclared command, or names another deprecated command | removing a capability instead of migrating it |
| `PV_REFUSED_STABILITY_OVERCLAIM` | a stability level is not supported by its `since`, an existing evidence path, or (for `stable`) a test that exists | "stable" as an adjective rather than a verified promise |
| `PV_REFUSED_SURFACE_INVALID` | the surface is structurally malformed: no command list, a duplicate name, an unknown kind, a malformed exit entry | reasoning about a declaration that is not a declaration |
| `PV_REFUSED_USAGE` | this tool's own invocation is malformed: an unknown action, a missing action or an unknown option | a tool that refuses its caller without saying which of its own codes it returned |

The detector imports nothing from the verifier. It starts it, reads its standard
output and exit status, and compares those with the declaration; a tool that
shared code with its subject could agree with it by construction. The stubs used
by the controls are test-only fixtures — they never appear in a shipped
configuration, and the controls never run against the real tree as their
subject.

Each property of the contract and the check that enforces it:

| property | enforced by |
|---|---|
| the command set | `PV_REFUSED_COMMAND_UNDOCUMENTED`, `PV_REFUSED_COMMAND_ABSENT` |
| the exit-code contract | `PV_REFUSED_EXIT_UNDEFINED`, `PV_REFUSED_EXIT_UNUSED` |
| the accepted arguments | `PV_REFUSED_HELP_DRIFT` |
| the JSON document's fields | `PV_REFUSED_JSON_FIELD` |
| determinism | `PV_REFUSED_UNSTABLE_OUTPUT` |
| the private-state rule | `PV_REFUSED_PRIVATE_STATE` |
| the schema version | `PV_REFUSED_UNVERSIONED_SCHEMA` |
| deprecation and its successor | `PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT` |
| the stability levels | `PV_REFUSED_STABILITY_OVERCLAIM` |
| the declaration's own structure | `PV_REFUSED_SURFACE_INVALID` |
| the detector's own command line | `PV_REFUSED_USAGE` |
| this document | `test_every_refusal_code_is_documented`, `test_the_contract_document_names_every_code_and_command` |
| the descriptive document's figures | `test_the_descriptive_document_no_longer_carries_the_stale_count` |
| the control set | `test_every_declared_code_has_a_control` |
| the recording of what the shape check cannot see | `test_every_recorded_discrepancy_still_reproduces` |

### 8.1 What the check does not see

A difference that leaves the listed surface unchanged is invisible to it. A flag
accepted and silently ignored, a private read the executable itself does not
declare, or a documented sentence that is simply wrong are all outside the
comparison. Those are found by reading the source, are recorded as
discrepancies with a re-checked witness in `evidence/a25/INVENTORY.json`, and
are corrected in a document or queued against a tool. The check's green result
means "no drift in the declared shape", not "no defect anywhere".

## 9. Known defects and their disposition

| id | finding | disposition |
|---|---|---|
| D1 | `list` is advertised as a subcommand and refused as one; the accepted form is `--list` | tool defect, queued; the descriptive document's table row is corrected |
| D2 | `--json` is accepted by `--list` and ignored; the listing stays TSV | tool defect, queued; both documents now name the exception |
| D3 | `--list` beats `--explain` beats a run; the precedence was undocumented | documented in §2.1 |
| D4 | `artifacts/phase2/install` is declared private but is outside the audited root set, so its presence is never reported | tool defect, queued; stated in §6 |
| D5 | the `private_state` entry counts are live readings inside the compared record | tool defect, queued; stated in §7 |
| D6 | the descriptive document's `test_verify.py` count said 19; the module executes 37 | corrected, old wording preserved in the A25 receipt |

Every entry's witness is re-checked by `evidence/a25/build_evidence.py`; a
finding that stops reproducing fails the producer rather than quietly remaining
in the record.

## 10. A worked example on a clean checkout

A fresh clone needs a Python 3.11 interpreter and nothing else: no court, no
network, no build, no private state, no toolchain.

```
$ git clone <repository> openssl-rs && cd openssl-rs

$ python3 forensics/tools/verify.py --list
manifest	required	in all
rebuild	required	in all
...
authority	optional	not in all
consumer-curl	required	in all
consumer-ssh	required	in all
consumer-sshd	required	in all

$ python3 forensics/tools/verify.py --explain manifest
manifest  (required; in `all`)
  needs:        git
  delegates to: forensics/tools/etp6_package.py
  establishes:  every input the tracked ETP-6 package manifest names is present at this commit with the recorded SHA-256
  does not:     does not establish that a package was ever built, archived or published, nor any property of its contents

$ python3 forensics/tools/public_surface.py verify
public-surface: 23 declared command(s) match the executable surface; exit codes 0, 1, 2 observed; 12 JSON field(s); 13 refusal code(s) available
public-surface: two-run determinism: listing stable; JSON document compared over 14 invocation(s)
public-surface: codes=PV_OK

$ python3 forensics/tools/public_surface.py explain manifest
public-surface: command=manifest kind=step stability=stable since=2026-11-23 (ETP-T12); this surface declared 2026-11-24 at a9bcb5480
public-surface: summary: check the tracked ETP-6 package manifest against this commit
public-surface: invocation: ['manifest']
public-surface: arguments: command, --json, --network, --explain, --list, --tmp, --help
public-surface: exit 0: the command is PASS [exit 0 is the PASS status of this command's own run; ...]
public-surface: exit 1: the command is not PASS: FAIL, BLOCKED or NOT_RUN [...]
public-surface: exit 2: the invocation was refused before any step ran [observed by unknown-command]
public-surface: json-form: document fields: candidate, counts, environment, interface, invocation, non_passing, private_state, root, schema, status, steps, warnings
public-surface: private-state: (none)
public-surface: prerequisites: git
public-surface: evidence: forensics/tools/verify.py, docs/PUBLIC-VERIFIER.md
public-surface: codes=PV_OK

$ python3 forensics/tools/verify.py authority --json > run.json; echo $?
1
$ python3 -c 'import json; d=json.load(open("run.json")); print(d["status"], d["non_passing"])'
FAIL ['authority']
```

The last command is not a failure of the contract: `authority` is a single
optional step that needs the network, the run declared none, so the step is
`NOT_RUN` and the run exits 1. `NOT_RUN` is the honest verdict and it is never a
pass.

Running a step command instead of `authority` exercises that step's own
prerequisite checks; on a clean checkout most are `NOT_RUN` or `FAIL`, and the
document records why. That is the interface working as declared.

## 11. Non-claims

* This contract is not a security boundary, a certification or a release gate.
  A clean `codes=PV_OK` means the declaration and the executable agree about the
  interface's shape at that candidate. It says nothing about whether any check
  is meaningful, correct or complete.
* The drift check is not a proof about the executable. It observes a finite set
  of invocations; a behaviour reachable only by another invocation is outside
  it, and §8.1 names the classes that are invisible by construction.
* The stability promise is about names, arguments, exit codes and fields — not
  about verdicts, timing, output prose or the set of steps. A step may begin
  returning `FAIL` at a new candidate without any contract change; that is the
  point of the contract.
* The declaration is not independent of its author. The same party wrote the
  declaration, the detector and the tests. It is a discipline against drift, not
  an independent audit (Earned Trust Articles 1, 2 and 5).
* No external party has driven this interface under this contract. Nothing here
  is external evidence.

## 12. `NOT_RUN`

* A run of `all` end to end, and of every step command, from a clean checkout
  under this contract. The contract's exit-code probes deliberately avoid them:
  `all` and the step commands need a court, a toolchain or the network, and
  their verdicts depend on the candidate's state rather than on the interface's
  shape.
* External reproduction of this contract by a party in a distinct trust domain.
* A machine-checked proof that the detector cannot miss a drift class; the
  refusal table and its controls are a finite, tested set, not a theorem.
* Repair of D1, D2, D4 and D5. They are queued with their witnesses; this
  item's scope is the declaration, the detector, the document and the records,
  and it does not change `verify.py`'s behaviour.
* The A25 queue row's preview of extended `verify` subcommands (`sarif`,
  `envelopes`, `attestations`, `signer-roles`, `provenance`, `transparency`,
  `revocations`, `policy`, `release`, …). They are not implemented; the surface
  declares only what is executable and does not pretend otherwise.
