# A25 receipt — the interface is declared, and the declaration is checked

## 1. Identity of this batch

| field | value |
|---|---|
| item | A25 (public verifier surface: a declared, versioned interface an outsider can discover and drive, with a drift detector that refuses when the declaration and the executable disagree) |
| branch | `staging` |
| HEAD at the start | `a9bcb54808eddfc11f7ab10215894e3c1064b21c` (`a24: a package an outsider can run, and an honest external status`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 33 7 0 5 12` (available **12** GiB); `Swap: 45 38 7` |
| `free -g` before the suite | `Mem: 45 33 6 0 6 12` (available **12** GiB); `Swap: 45 39 6` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), repository at `/work`; reused, not restarted |
| interpreter in the court | Python **3.11.2** (the host runs 3.14.10; the records are byte-identical on both) |
| heavy commands | one at a time; no Rust build |

The host had 12 GiB available before the work and before the suite, below the
24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed — every
gate is Python — and the derived cap `min(8, available − 16)` is negative, below
the 2 GiB floor, so **no new court was started**. The already-running court with
its hard 6 GiB cap was reused, and every gate that reads or runs the tree ran
inside it. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/public_surface.py` | 1,168 | the detector: `inventory`, `verify`, `explain`; the surface-driven discovery, the shape comparison, the thirteen stable refusal codes; CLI exit 0/1/2, always printing the code, including for its own usage errors. It imports nothing from the verifier it checks |
| `forensics/tools/tests/test_public_surface.py` | 543 | 39 controls: inventory-vs-surface, exit-code observation or basis, two-run listing identity, JSON-field identity, help/prerequisite/private-state agreement, one control per refusal code plus a faithful-stub positive, determinism of the check itself, CLI exit codes (including the usage and help paths), document synchronisation, and the six re-checked source-reading witnesses |
| `docs/PUBLIC-VERIFIER.md` | 442 | the normative contract: discovery, precedence, the command table, the exit-code contract, the JSON schema and its twelve fields, the three stability levels, the private-state rule, determinism, the thirteen-code refusal table with an enforcement table, the six known defects, a clean-checkout worked example, non-claims, `NOT_RUN` |
| `evidence/a25/build_evidence.py` | 977 | deterministic producer: embeds the declaration, measures the executable, runs the fifteen controls, re-checks every discrepancy witness, writes four records, exits nonzero on any disagreement |
| `evidence/a25/SURFACE.json` | 1,689 | the declaration: `schemaVersion`, `exitCodeContract`, `discovery`, eight exit probes, seven arguments, the private-state/determinism/stability rules, and 23 command entries |
| `evidence/a25/INVENTORY.json` | 2,263 | the executable surface as observed: 20 listing rows, 20 explain blocks, the eight probe results, the twelve JSON fields, and six discrepancies with re-checked witnesses |
| `evidence/a25/VERIFY.json` | 1,263 | the comparison: eight named checks, per command declared-vs-observed, the fourteen invocations used, `ok: true`, `codes: ["PV_OK"]` |
| `evidence/a25/CONTROLS.json` | 402 | 15 `controlOnly` rows: thirteen refusal codes (the JSON code twice, the CLI-usage code run against the detector itself) and a faithful-stub positive control; every row matched |
| `docs/PUBLIC-VERIFICATION.md` | 5 edits | 9 insertions, 5 deletions: four minimal corrections (D1, D2, D5, D6); the old wording is preserved in §6 below |
| `docs/ETP-TODO.md` | 1 row | the A25 row replaced from `TODO`; no other row touched |
| `evidence/a25/RECEIPT.md` | this file | the receipt |

Content digests (SHA-256, full):

| file | sha256 |
|---|---|
| `public_surface.py` | `a5b54814cf0bad654e1c081eaf0153f2e9579f6ac59f1dfd177613759acdd95b` |
| `test_public_surface.py` | `f0e642b87b18056154c9d94f8bc6a41dc4682216b23172c33019ea645e24ffb2` |
| `build_evidence.py` | `e241cda138ce1092a6f84d4efc3cf783bf714d3f37ea861e1982ca5638eda073` |
| `PUBLIC-VERIFIER.md` | `28e1a64916e41cd30cdd3ffa4cbed584100e4080f151fbd63231973f1caa7618` |
| `PUBLIC-VERIFICATION.md` | `6c6c6ed838e4bc50dbb45f0e523487bd45d211f888691aecb51407f791dedadf` |
| `verify.py` (subject, unmodified) | `17a9f2ae75614eaff52dd0bd833e30af05721e53a957e6209f68f1fa3fed4fc3` |
| `SURFACE.json` | `ffca67d057b05000691aef50b4edf900e284cc5d6c22e92ec866eb8931f57352` |
| `INVENTORY.json` | `ad29b43909589977135ef29160a461a182c2a20446ea2a9a3adc0efb80fd67ca` |
| `VERIFY.json` | `031abfff606fdb469c053fcca3b1a3737537c9f082dd6d070fa63f634ca5cb53` |
| `CONTROLS.json` | `bc0dbf36afc8190e4065158855600dc524663b54391df947abe024a158ea613c` |

`INVENTORY.json`, `VERIFY.json` and `CONTROLS.json` name their producing tool and
its digest (`producer`/`detector`), so an edit to either tool invalidates the
records until the producer is re-run. `SURFACE.json` carries no producer stamp:
it is the declaration, the input the other three are measurements against.

## 3. The contract

> **An interface is public only if its shape is declared, and the declaration is
> compared with the executable on every run.** The commands, their arguments,
> their exit codes, the JSON document's fields and the stability level must be in
> a machine-readable record; a disagreement is a refusal with a stable code, not
> a warning. And a green comparison says only that the two agree about the
> *shape*: it does not say that any check is meaningful, and it cannot see a
> difference that leaves the listed surface unchanged.

The declaration is `evidence/a25/SURFACE.json` (schema
`openssl-rs/public-surface/1`). The four properties the item names each have a
refusal:

| property | refusal |
|---|---|
| no hidden command | `PV_REFUSED_COMMAND_UNDOCUMENTED`, `PV_REFUSED_COMMAND_ABSENT` |
| no undocumented exit | `PV_REFUSED_EXIT_UNDEFINED`, `PV_REFUSED_EXIT_UNUSED` |
| no private-state dependency | `PV_REFUSED_PRIVATE_STATE` |
| no nondeterministic output | `PV_REFUSED_UNSTABLE_OUTPUT` |

plus `PV_REFUSED_HELP_DRIFT` (arguments), `PV_REFUSED_JSON_FIELD` (the document),
`PV_REFUSED_UNVERSIONED_SCHEMA` (the schema), `PV_REFUSED_STABILITY_OVERCLAIM` and
`PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT` (the promise),
`PV_REFUSED_SURFACE_INVALID` for a declaration that is not a declaration, and
`PV_REFUSED_USAGE` for the detector's own malformed command line.

The detector (`public_surface.py`) starts the verifier, reads `--list`, `--help`,
`--explain`, two `--json` runs and eight exit probes, and compares. It imports
nothing from the verifier, so it cannot agree with it by construction, and its
own controls run against test-only stubs rather than against the real tree.

## 4. The inventory, the discrepancies, and the verify result

**Observed (from the executable, not from a document):**

* `--list` prints **20** rows; `--explain` prints **20** blocks; every listing
  name is a declared step and every declared step is listed and explained.
* Two further commands exist and are declared: `list` (`--list`) and `explain`
  (`--explain`), plus the aggregate `all`. `--list` does not print them, so the
  surface declares them as `discovery`/`aggregate` and proves each with a
  declared probe.
* The accepted arguments are `command`, `--json`, `--network`, `--explain`,
  `--list`, `--tmp TMP` and `--help` (`-h`); the help text names exactly those,
  and it names `all` and `list` as commands.
* Exit codes **0, 1 and 2** are each observed without running a step:
  `--list`/`--help`/`--explain`/`--explain all` → 0; `authority` with no network
  declared → `NOT_RUN`, a single optional step gating on itself → 1; an unknown
  subcommand, a missing option value and `--explain` of an unknown name → 2.
* The document's top-level fields are exactly the twelve declared:
  `candidate`, `counts`, `environment`, `interface`, `invocation`,
  `non_passing`, `private_state`, `root`, `schema`, `status`, `steps`,
  `warnings`.
* Two `--list` runs are byte-identical; two `authority --json` runs are
  byte-identical outside the declared `environment` block.

**Discrepancies found by reading the code** (`INVENTORY.json#discrepancies`;
every witness is re-checked by the producer, and a witness that stops
reproducing fails it):

| id | finding | class |
|---|---|---|
| D1 | `list` is advertised as a subcommand (`--help`: "a subcommand name, `all`, or `list`"; the refusal message lists it; `main` writes `args.command or "list"`) and refused as one: `verify.py list` and a bare `verify.py` both exit 2. The accepted form is `--list` | tool defect, queued; document corrected |
| D2 | `--json` is accepted by `--list` and ignored: the listing stays TSV, because the listing branch returns before serialisation | tool defect, queued; both documents now name the exception |
| D3 | `--list` takes precedence over `--explain`, which takes precedence over a run; `--json`/`--network`/`--tmp` have no effect on the discovery commands. Undocumented | now in the contract |
| D4 | the consumer commands declare `artifacts/phase2/install` private, but the audited root set names `artifacts/phase2/shell`, so the declared path is never counted and `private_state_present` can never report it | tool defect, queued; stated as a known gap |
| D5 | the top-level `private_state` entry counts are live `git status` readings inside the compared record, while only `environment` is declared as an input | tool defect, queued; one clause added to the descriptive document |
| D6 | the descriptive document said `test_verify.py` holds 19 tests in two places; the module executes 37 | document defect, corrected |

**`python3 forensics/tools/public_surface.py verify` → exit 0, no code fired:**

```
public-surface: 23 declared command(s) match the executable surface; exit codes 0, 1, 2 observed; 12 JSON field(s); 13 refusal code(s) available
public-surface: two-run determinism: listing stable; JSON document compared over 14 invocation(s)
public-surface: codes=PV_OK
```

What that green line means: the declaration and the executable agree about the
command set, the arguments, the exit codes, the document's fields, the private
read declarations, two-run determinism and the stability support. What it does
not mean is stated in §8 and in the document's §11.

## 5. The controls

`evidence/a25/CONTROLS.json` holds 15 rows, every one `controlOnly`. Each is a
stub verifier written into a temporary directory, an in-memory mutation of the
declaration, or — for the usage code — the detector invoked with an unknown
action. None is a shipped configuration, none edits `verify.py`, and the stub is
written to imitate the real verifier so that only the defect under test can fire.

| control | code observed |
|---|---|
| `faithful-stub` (positive) | `PV_OK`, no finding |
| `undocumented-command` | `PV_REFUSED_COMMAND_UNDOCUMENTED` |
| `absent-command` | `PV_REFUSED_COMMAND_ABSENT` |
| `undefined-exit` | `PV_REFUSED_EXIT_UNDEFINED` |
| `unused-exit` | `PV_REFUSED_EXIT_UNUSED` |
| `help-drift` | `PV_REFUSED_HELP_DRIFT` |
| `json-extra-field` | `PV_REFUSED_JSON_FIELD` |
| `json-missing-field` | `PV_REFUSED_JSON_FIELD` |
| `unstable-output` | `PV_REFUSED_UNSTABLE_OUTPUT` |
| `undeclared-private-state` | `PV_REFUSED_PRIVATE_STATE` |
| `unversioned-schema` | `PV_REFUSED_UNVERSIONED_SCHEMA` |
| `deprecated-without-replacement` | `PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT` |
| `stability-overclaim` | `PV_REFUSED_STABILITY_OVERCLAIM` |
| `duplicate-command` | `PV_REFUSED_SURFACE_INVALID` |
| `malformed-invocation` | `PV_REFUSED_USAGE` |

`codesCovered` is 13 of 13; `failing` is 0. Each row asserts its **exact** code
set, so an extra refusal cannot hide behind a matching one.

## 6. Defects found

**Existing records.** Four descriptive-document corrections (D6 twice, D1, D2, D5)
and one interface defect (D4):

* **D6 — the descriptive document's live figure was stale.** Old:
  `test_verify.py` "(19 tests, `unittest`)" in the header and "(19 tests)" in §8.
  New: "(37 tests, `unittest`)" and "(37 tests)". The figure is a live quantity
  in a hand-written document that no generator corrects; the executed count is
  37 (the file defines 38 `def test_` names, one of which, `test_ok`, is a helper
  the loader does not collect). `evidence/etp-t12/RECEIPT.md` records 19
  correctly for the run it describes at `6c174518e`; the defect is that the
  descriptive document kept that historical figure as a live one. The previous
  item that touched the surrounding wording (`evidence/gate-reliability/RECEIPT.md`
  §7) recorded a different sentence there and left it out of scope; that one has
  since been repaired and this one had not been recorded by any gate.
* **D1 — the descriptive document's subcommand table said `list`.** Old:
  ``| `list` | `python3` | — | the subcommand set and its role in `all` | — |``.
  New: ``| `--list` | `python3` | — | the subcommand set and its role in `all` | — |``.
  The table's header still says "subcommand"; the row now names the accepted form.
  The tool defect behind it is queued, not repaired.
* **D2 — the descriptive document's `--json` sentence had no exception.** Old:
  "`--json` emits one sorted, timestamp-free document: per step `name`, `status`, …".
  New: "`--json` (on a step run or on `all`; `--list` and `--explain` print their
  text regardless, because they are discovery commands rather than step runs)
  emits one sorted, timestamp-free document: per step `name`, `status`, …".
* **D5 — the descriptive document's determinism sentence claimed too much.** Old:
  "Two runs over the same checkout with the same inputs are byte-identical in
  everything except that declared block." New: "… in everything except that
  declared block and the `private_state` entry counts, which are live readings of
  the working tree's untracked or ignored entries and not of the checkout (A25
  D5)." The claim was right for a quiescent tree and wrong as a general statement;
  the tool behaviour that makes it wrong is queued, so the prose now states the
  actual scope rather than an intention.
* **D4 — an existing interface defect, recorded not repaired.**
  `docs/PUBLIC-VERIFICATION.md` §4 says a declared private path "is either
  declared by the step and reported as present, or absent and reported as
  absent". For `artifacts/phase2/install` the executable cannot do the first half,
  because that path is not in the audited root set. The sentence is left
  unedited: the defect is the tool's, and the item that repairs it must re-derive
  the presence fields. It is queued in §8.

**Development defects found in this batch's own machinery** (recorded, because a
control that passes for the wrong reason is the defect this item exists to
catch):

* The first `undefined-exit` control mutated the only probe that observed exit 1,
  so it fired `PV_REFUSED_EXIT_UNDEFINED` **and** `PV_REFUSED_EXIT_UNUSED` and
  the exact-set assertion rejected it. The control was corrected to mutate a
  probe whose code is observed twice (unknown subcommand → 7), not the check.
* The first `unstable-output` fixture set a `vary` flag but the document carried
  no placeholder for the run counter, so the two runs were identical and the
  control observed **no** code. The fixture now writes the counter into a
  declared field's value, so the field set stays valid and only the value moves.
* The first test-count witness counted tests with
  `loadTestsFromName("forensics.tools.tests.test_verify")`, which resolves
  through a different package root and returned 0 — the witness failed and the
  producer refused to write the record. It now uses the runner's own
  `discover`, which is the count that matters.
* The first `enforced by` test selected table rows by the phrase rather than by
  the table, so it found zero rows; it now reads the table after its header.
* The declaration's first draft declared the positional `command` among the
  help's *option* tokens, which are by definition only `-`-prefixed; the test now
  separates options from the positional and asserts each separately.
* The detector's own command line did not print a code when its own invocation
  was malformed: `public_surface.py bogus-action` exited 2 with argparse's usage
  message and nothing else, so "always printing the code" held for every path
  except the tool's own usage error. Old: no code on that path. New:
  `PV_REFUSED_USAGE` is a thirteenth stable code, `parse_args` is wrapped so the
  code line is printed after argparse's message, and `--help` prints `PV_OK`. The
  added `test_a_malformed_invocation_prints_a_code`, `test_help_prints_a_code`
  and the `malformed-invocation` control hold it; the code count in every record
  and in the contract moved from twelve to thirteen.

No gate rejected an existing record. No check was relaxed, no expected value was
changed, and `verify.py` was not modified.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 33 7 0 5 12` (available 12 GiB); `Swap: 45 38 7` |
| memory before the suite | `free -g` (host) | `Mem: 45 33 6 0 6 12` (available 12 GiB); `Swap: 45 39 6` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `CARGO_BUILD_JOBS=4 python3 -m unittest discover -s forensics/tools/tests` | `Ran 1834 tests in 419.870s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,795 pre-existing tests are present (1,795 + 39), none removed, none ignored |
| focused A25 controls | `python3 -m unittest forensics.tools.tests.test_public_surface` | `Ran 39 tests in 8.833s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `SURFACE.json`, `INVENTORY.json`, `VERIFY.json`, `CONTROLS.json` | `json.tool ok: SURFACE`, `json.tool ok: INVENTORY`, `json.tool ok: VERIFY`, `json.tool ok: CONTROLS` |
| producer, two runs | `python3 evidence/a25/build_evidence.py` twice in the court | both: `a25: base=a9bcb5480 commands=23 steps=20 json-fields=12 discrepancies=6 control-codes=13 controls=15 failing=0 witnesses-not-reproduced=0 verify=PV_OK`, exit 0 |
| producer byte-identity | `sha256sum` over the four records before, after run 1, after run 2 | `diff` before vs run 1: `run1 identical`; run 1 vs run 2: `run2 identical`. A host run (Python 3.14.10) against the court's four digests printed `SURFACE.json: OK`, `INVENTORY.json: OK`, `VERIFY.json: OK`, `CONTROLS.json: OK`, so the records are byte-identical across the two venues |
| the surface check | `python3 forensics/tools/public_surface.py verify` | `23 declared command(s) match … 13 refusal code(s) available`; `codes=PV_OK`; exit 0. **No refusal code fired** |
| the inventory | `python3 forensics/tools/public_surface.py inventory` | `commands=23 steps=20 json-fields=12 source-findings-carried=0`; `exit codes observed 0, 1, 2; listing stable=True; listing-with-json emits a document=False`; `codes=PV_OK`; exit 0 |
| one command's contract | `python3 forensics/tools/public_surface.py explain manifest` | printed the twelve declared fields, exit codes 0/1/2 with their observation basis, and `codes=PV_OK`; exit 0 |
| worktree | `git --no-pager status --porcelain` | see §10 |

## 8. Obligations retained

* **D1, D2, D4, D5 are open tool defects.** Each has a re-checked witness, a
  named wrong conclusion, and a queued repair: make `list` a subcommand or
  remove it from the help; honour or reject `--json` on the discovery commands;
  add `artifacts/phase2/install` to the audited root set (or stop declaring it
  private); declare the `private_state` readings as an input (or project them out
  of the compared record). None was repaired here, because this item's scope is
  the declaration, the detector, the document and the records, and it does not
  change `verify.py`'s behaviour.
* **The declaration, the detector and the tests share an author.** This is drift
  discipline, not an independent audit (Earned Trust Articles 1, 2 and 5).
* **The check sees shape, not behaviour.** A flag accepted and silently ignored,
  a private read the executable itself does not declare, or a wrong sentence are
  invisible to it; the six discrepancies are the evidence that source reading is
  still required. `PV_OK` is not a claim that the interface has no defect.
* **The stability promise is not yet exercised.** No command is `deprecated` or
  `experimental`, so the replacement and migration paths have controls but no
  real instance. The levels are a truthful option for a future change, not a
  used mechanism.
* **Evidence identity.** Every record names base `a9bcb5480`; `INVENTORY`,
  `VERIFY` and `CONTROLS` name the producing tool and detector by digest. An edit
  to either tool, or to the declaration, invalidates the records until the
  producer is re-run.
* **The A25 queue row's original scope is not delivered.** Its parenthetical
  previewed fourteen `verify` subcommands; `freshness`, `controls` and `all`
  exist, and `sarif`, `sarif-completeness`, `evidence-manifest`, `envelopes`,
  `attestations`, `signer-roles`, `provenance`, `transparency`, `revocations`,
  `policy` and `release` do not. The surface declares only what is executable and
  does not pretend otherwise; the eleven absent commands remain an obligation of
  the programme, not of this item.

## 9. `NOT_RUN`

* A run of `all`, or of every step command, from a clean checkout under this
  contract. The declared exit-code probes deliberately avoid them: they need a
  court, a toolchain or the network, and their verdicts depend on the candidate's
  state rather than on the interface's shape.
* A run from an actual `git clone` in a fresh container. The check is
  checkout-scoped and needs only an interpreter and the tracked tree; that it
  works on a clone follows from it reading nothing else, and was not executed.
* External reproduction of this contract by a party in a distinct trust domain.
* A machine-checked proof that the detector misses no drift class, and a proof
  that the declaration is complete.
* Repair of D1, D2, D4 and D5; and the eleven absent extended subcommands.
* A BOUNDARY audit, a SEAL and the Rust test suite — no Rust source was modified.
* The descriptive document's §7 clean-checkout run, which records a past moment
  and was not re-executed.

## 10. Forward-freeze member and worktree

`evidence/a17/FREEZE-forward.json` declares **one** A25 member:

* **satisfied:** `a25-receipt` — `evidence/a25/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

The freeze remains `state: OPEN`; it was not amended and not closed, and this
receipt claims no other member.

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
 M docs/PUBLIC-VERIFICATION.md
?? docs/PUBLIC-VERIFIER.md
?? evidence/a25/
?? forensics/tools/public_surface.py
?? forensics/tools/tests/test_public_surface.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row (A25),
and `docs/PUBLIC-VERIFICATION.md` in the five edits for four findings enumerated
in §6.

---

## 11. Correction — the records re-derived at `f2ec25379`

**Appended 2026-11-24. Sections 1–10 above are preserved unedited**: they are the
record of what was established at `a9bcb5480`. This section supersedes their
digests and their statement that four defects are "queued", and records the
re-derivation performed after the repairs landed.

### 11.1 Base and cause

| field | value |
|---|---|
| branch / HEAD at the start of the refresh | `staging` / `f2ec25379e3ba8f663a93aedf514bcb1fd9cb674` ("repair: make the discovery commands and the declared inputs do what they say") |
| worktree | clean (`git --no-pager status --porcelain` printed nothing) |
| `free -g` before the refresh | `Mem: 45 32 7 0 6 13` (available **13** GiB); `Swap: 45 40 4` |
| `free -g` before the suite | `Mem: 45 32 6 0 6 12` (available **12** GiB); `Swap: 45 40 4` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, `HostConfig.Memory` = `MemorySwap` = `6442450944` (6 GiB), status `running`; reused, not restarted; Python **3.11.2** |
| heavy commands | one at a time; no Rust build (none was needed and available memory is below the 24 GiB floor) |

A new court was not started: the derived cap `min(8, available − 16)` is negative
and below the 2 GiB floor, so §6.1's rule is to reuse the capped court, which is
what every command in this section did.

**Cause.** A25 declared the surface and measured it at `a9bcb5480`. The D1–D5
batch (`evidence/defects/d1-d5/RECEIPT.md`) then repaired four tool defects in
`verify.py`, changed `public_surface.py` to match, and hand-edited
`SURFACE.json` so the gate would still pass — but it deliberately did not
regenerate the other three records and did not run the producer. The result was
exactly the defect class A25 exists to catch, in A25's own records:

* `INVENTORY.json` still asserted that `list` was refused and that
  `--list --json` was TSV, and its D1–D5 witnesses no longer reproduced;
* `VERIFY.json` recorded the same pre-repair observations;
* `build_evidence.py` still *authored* the pre-repair declaration (`list`
  `jsonForm: none`, the `artifacts/phase2/install` private declaration, the D4
  and D5 `knownGap` clauses, `listJson.emitsJson: false`) and its control stubs
  imitated the pre-repair verifier, so re-running it would have rewritten
  `SURFACE.json` back to the defective declaration; and
* `declaredAtCommit` was `a9bcb5480`, a value the producer could not relate to
  the measured sources at all.

### 11.2 What the refresh changed

`evidence/a25/build_evidence.py` is now the single source of the declaration and
the records. It gained an explicit declaration identity instead of a constant or
a live `HEAD`:

* `--declared-at COMMIT`, defaulting to the `declaredAtCommit` already in
  `SURFACE.json` when a record exists (and to `HEAD` only when there is no
  record). The reproduction path never reads `HEAD`.
* `declaredSources`: the SHA-256 of `forensics/tools/verify.py` and
  `forensics/tools/public_surface.py`, the two files the declaration is *about*.
  The producer itself is deliberately not one of them: its digest is written
  into the records, and a declaration cannot be bound to the bytes of the
  program that writes it.
* Three named refusals, each of which writes nothing and exits 3:
  `A25_REFUSED_DECLARED_SOURCE_MOVED` (a recorded declaration no longer matches
  the measured source), `A25_REFUSED_DECLARED_AT_UNKNOWN` (the named commit is
  not in the repository) and `A25_REFUSED_DECLARED_AT_MISMATCH` (the named
  commit does not carry the measured source).

The declaration itself was re-derived from the executable, not copied from the
old records: `list`/`--list` declare the listing document
(`openssl-rs/verify-listing/1`, fields `commands`/`interface`/`schema`), the
consumer commands declare `court` only, the audited-root rule is the derived
set, the determinism rule names both declared inputs and records no known gap,
and a ninth exit probe (`list-subcommand`) observes the repaired dispatch.

The records were regenerated, and the discrepancy list became historical: D1,
D2, D4 and D5 are `status: repaired` at `f2ec25379` and carry both the old
behaviour with its witness (`historicalWitness`, `observedAt` `a9bcb5480`,
expected **not** to reproduce) and a live witness for the repaired behaviour
(which must reproduce). D3 and D6 remain documentation corrections. One new
discrepancy was found while re-deriving:

* **D7 — `--json` is accepted by `--explain` and `--help` and ignored.** D2
  repaired the listing only. `verify.py --explain --json` and
  `verify.py --help --json` exit 0 and print text. The contract states the
  exception (§2.1, §2.2, §4) and the surface declares `explain` as
  `jsonForm: none`, so the declaration and the executable agree; the
  executable's own `--help` sentence names only the listing exception, so a
  caller reading only `--help` would expect a document. Recorded and queued
  against that prose; not repaired here, because changing it means changing
  `verify.py`, which this record measures.

### 11.3 Old records, old digests, new digests

SHA-256, full. "A25" is the state §1–§2 above describe; "intermediate" is what
the D1–D5 batch left (only `SURFACE.json` was edited by hand; the other three
records were untouched and therefore still carried the A25 digests, which is why
they no longer described the executable).

| file | A25 (old) | intermediate (stale) | new (`f2ec25379`) |
|---|---|---|---|
| `SURFACE.json` | `ffca67d057b05000691aef50b4edf900e284cc5d6c22e92ec866eb8931f57352` | `34c5ec0c1a4bb36d92277cfbbeccea8154fe5211258b22a21eb0475ebc6de4cb` | `c523876b1e11521f746b92c2554b84d32a315ff2b877dceb7732d6d74f95067e` |
| `INVENTORY.json` | `ad29b43909589977135ef29160a461a182c2a20446ea2a9a3adc0efb80fd67ca` | same as A25 (untouched) | `7a540848a08b60d65d69b1dfded0d66fedb0e37e9f75d83fc2cd260fdf9ab926` |
| `VERIFY.json` | `031abfff606fdb469c053fcca3b1a3737537c9f082dd6d070fa63f634ca5cb53` | same as A25 (untouched) | `2731fe494c694451ddeb69e9c2c8ffcc0bae63d1cf6d6f2343c7d755627916c2` |
| `CONTROLS.json` | `bc0dbf36afc8190e4065158855600dc524663b54391df947abe024a158ea613c` | same as A25 (untouched) | `025b5b76e4e71c9a09ed83649837e600271f704b40bf79187f5185d82a6e15b6` |
| `build_evidence.py` | `e241cda138ce1092a6f84d4efc3cf783bf714d3f37ea861e1982ca5638eda073` | same as A25 (untouched) | `3983ccc04919b9360e837ee3523e874e99e32a8538ac08227b5531ef333778e3` |

The two sources the declaration is about, unchanged by this refresh and bound
into `declaredSources`:

| source | sha256 |
|---|---|
| `forensics/tools/verify.py` | `1d7d6f6a1debc1d7fa09f2eb3f30228249f75d06557498ca6c1a80e9cf8381f7` |
| `forensics/tools/public_surface.py` | `b21c03ff71093ff34a2bfdde14853baf031b4cf49f2b41ccc1c0ea292bb51022` |

### 11.4 D1, D2, D4 and D5 — before and after, as re-derived

| id | before (`a9bcb5480`, as recorded by A25) | after (`f2ec25379`, observed now) |
|---|---|---|
| D1 | `verify.py list` → exit 2, `unknown subcommand 'list'`; bare `verify.py` → exit 2, same message | `verify.py list` → exit 0, listing; bare `verify.py` → exit 2, `verify: no subcommand; pass a command name, \`all\`, or \`list\` (\`--list\` prints the listing)` |
| D2 | `--list --json` → exit 0, TSV head `manifest\trequired\tin all`; `verify.py` had no `LISTING_SCHEMA` | `--list --json` and `list --json` → exit 0, JSON object with fields `commands`, `interface`, `schema`, 20 rows; the two forms byte-identical |
| D4 | `--explain consumer-curl` printed `private:      court, artifacts/phase2/install`; `known_roots` omitted `install` | `--explain consumer-curl` prints `private:      court`; every declared read is inside `private_state.known_roots`; `install` is 155 Git-tracked files with no untracked or ignored entry and is no longer claimed private |
| D5 | `private_state` had no `declared` key and sat inside the compared record | `private_state.declared == "private-state-input"`, `known_roots` non-empty, excluded from the two-run projection alongside `environment`; `INPUT_KEYS` exists in `verify.py` |

The old expectations are preserved in `INVENTORY.json` as `historicalWitness`
entries, and the producer now **fails** if any of them reproduces again (a
regression), as well as if a live witness stops reproducing.

### 11.5 The control fixtures were stale, and said so

The first producer run at this candidate refused: `faithful-stub` observed
`PV_REFUSED_EXIT_UNDEFINED`, `PV_REFUSED_JSON_FIELD` and
`PV_REFUSED_UNSTABLE_OUTPUT` instead of no finding, and every other control
carried those three extra codes — fourteen failing rows. That is the correct
behaviour of a control that asserts its exact code set: the stub still imitated
the pre-repair verifier (no `list` probe response, a TSV `--list --json`, and a
`private_state` with no `declared` marker). The fixtures were updated to imitate
the repaired verifier (`list` and `list --json` responses; a listing document
derived from the same rows; a declared, populated private-state input), and all
15 rows then observed exactly their declared code. No control's *expected* code
set was changed.

### 11.6 The test that asserted the stale record

`forensics/tools/tests/test_public_surface.py` contained one control that
asserted the old record as a live fact. It was corrected to assert the newly
observed fact — one live witness set that reproduces, one historical set that
must not, and the four repairs naming `f2ec25379`. The old expectation, quoted
verbatim:

```python
        self.assertEqual([entry["id"] for entry in inventory["discrepancies"]],
                         ["D1", "D2", "D3", "D4", "D5", "D6"])
        for entry in inventory["discrepancies"]:
            self.assertTrue(entry["witness"], entry["id"])
            for witness in entry["witness"]:
                self.assertTrue(witness["reproduced"],
                                f"{entry['id']} witness no longer reproduces: "
                                f"{witness}")
```

This is not a weakened check: the new assertion rejects a stale live witness, a
regressed repair, a historical witness recorded against the wrong candidate, a
repair that names its own discovery candidate, and a repair with no preserved
old witness. No test was removed, skipped or newly ignored; the file is still
39 controls.

### 11.7 Gates at the refreshed candidate

All commands ran in the reused 6 GiB court, one at a time.

| gate | command | exact result |
|---|---|---|
| memory | `free -g` | `Mem: 45 32 7 0 6 13` (available 13 GiB), `Swap: 45 40 4`; before the suite `Mem: 45 32 6 0 6 12` (12 GiB) |
| court | `docker inspect openssl-rs-court` / `status` | `6442450944 6442450944 running`; `memory.max 6442450944`, `oom=1 oom_kill=1` (historical); reused, no build |
| focused controls | `python3 -m unittest forensics/tools/tests/test_public_surface.py` | `Ran 39 tests in 9.392s` / `OK` |
| whole tools suite | `CARGO_BUILD_JOBS=4 python3 -m unittest discover -s forensics/tools/tests` | `Ran 1843 tests in 422.237s` / `OK` / `closure discipline self-test: 7 control groups passed`; 1,843 = the parent's 1,843, none removed, none newly ignored |
| producer, run A | `python3 evidence/a25/build_evidence.py --declared-at f2ec25379e3ba8f663a93aedf514bcb1fd9cb674` | `a25: declared-at=f2ec25379 commands=23 steps=20 json-fields=12 discrepancies=7 repaired=4 control-codes=13 controls=15 failing=0 witnesses-not-reproduced=0 regressed-repairs=0 verify=PV_OK`; exit 0 |
| producer, run B | `python3 evidence/a25/build_evidence.py` (default `--declared-at` from the record) | the same line; exit 0; `diff` of the four digests: `A==B byte-identical` |
| refusal: unknown commit | `python3 evidence/a25/build_evidence.py --declared-at 0000…0000` | `a25: refused codes=A25_REFUSED_DECLARED_AT_UNKNOWN`; exit 3; records byte-identical before/after |
| refusal: commit without the measured source | `python3 evidence/a25/build_evidence.py --declared-at a9bcb5480` | `a25: refused codes=A25_REFUSED_DECLARED_AT_MISMATCH` / `commit a9bcb5480 does not carry the declared sources [...]`; exit 3; records untouched |
| refusal: source moved | one comment appended to `verify.py`, then the default run; file restored | `a25: refused codes=A25_REFUSED_DECLARED_SOURCE_MOVED` … `recorded 1d7d6f6a… != measured 3126c9ed…`; exit 3; records untouched; `git status --porcelain -- forensics/tools/verify.py` empty after restore |
| surface check | `python3 forensics/tools/public_surface.py verify` | `public-surface: 23 declared command(s) match the executable surface; exit codes 0, 1, 2 observed; 12 JSON field(s); 13 refusal code(s) available` / `public-surface: two-run determinism: listing stable; JSON document compared over 15 invocation(s)` / `public-surface: codes=PV_OK`; exit 0 |
| JSON | `python3 -m json.tool` on the four records | `json.tool ok: SURFACE`, `INVENTORY`, `VERIFY`, `CONTROLS` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; exit 0 |
| worktree | `git --no-pager status --porcelain` | see §11.9 |

### 11.8 What was preserved, and where

* **The prior receipt** — §§1–10 of this file are unedited; they remain the
  record of the `a9bcb5480` measurement, including its now-superseded digests
  and its "queued" descriptions of D1/D2/D4/D5.
* **The old behaviour of every repaired defect** — `INVENTORY.json`'s
  `historicalWitness` entries (the old argv/expected text, `observedAt`
  `a9bcb5480`, `supersededAt` `f2ec25379`), plus `evidence/defects/d1-d5/RECEIPT.md`
  §3–§5, which is not modified.
* **The old document wording** — `evidence/defects/d1-d5/RECEIPT.md` §4 quotes
  it verbatim; the contract's §9 now names the "repaired at" commit for each
  entry instead of dropping the entry.
* **The old test expectation** — quoted in §11.6 above.
* **The old digests** — the table in §11.3.
* **The descriptor of the stale record** — the intermediate `SURFACE.json`
  digest (`34c5ec0c…`) is recorded in §11.3 so the hand-edited state is
  distinguishable from both A25 and the refresh.

### 11.9 Files changed in this refresh

```
 M docs/ETP-TODO.md                     (the A25 row, in place)
 M docs/PUBLIC-VERIFIER.md              (§9 only: "repaired at" column, D7, the historical-witness paragraph)
 M evidence/a25/CONTROLS.json           (regenerated)
 M evidence/a25/INVENTORY.json          (regenerated)
 M evidence/a25/RECEIPT.md              (this section appended)
 M evidence/a25/SURFACE.json            (regenerated)
 M evidence/a25/VERIFY.json             (regenerated)
 M evidence/a25/build_evidence.py       (declaration identity, freeze refusals, historical discrepancies, updated stubs)
 M forensics/tools/tests/test_public_surface.py (one stale assertion corrected; 39 controls unchanged)
```

No other path changed. In particular `forensics/tools/verify.py`,
`forensics/tools/public_surface.py`, `docs/PUBLIC-VERIFICATION.md`, `src/`,
`docker/` and `AGENTS.md` are untouched, and nothing was committed or pushed.

### 11.10 Anything not established

* **A run at a later commit.** No commit was made, so the literal
  "re-run at a later commit reproduces byte-for-byte" was not executed. What was
  established is the mechanism (the reproduction path never reads `HEAD`; it
  uses `declaredAtCommit` from the record) and two byte-identical runs, the
  second taking the recorded value by default. The literal case is `NOT_RUN`.
* **Independent verification.** The same party wrote the refresh and its
  controls. `PV_OK`, the 15 controls and the producer are a finite tested set,
  not an independent audit (Earned Trust Articles 1, 2 and 5).
* **D7's repair.** It is recorded and queued; the `--help` prose is unchanged
  because changing it means changing `verify.py`.
* **The shape check still cannot see behaviour.** It agrees with the
  declaration; the discrepancies are the evidence that reading the source is
  still required. `PV_OK` is not "no defect".
* **Freshness/closure of the downstream consumer families** and the eleven
  absent extended `verify` subcommands are unchanged obligations, as in §8.
