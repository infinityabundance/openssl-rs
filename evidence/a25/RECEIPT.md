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
