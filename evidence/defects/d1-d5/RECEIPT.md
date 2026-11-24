# Receipt — repair of the four tool defects A25 recorded (D1, D2, D4, D5)

**Batch:** one bounded batch, `defects/d1-d5`.
**Base:** `0ea00ac4d4c57cf418046b350805a059218ccd99` (branch `staging`,
`origin/staging`), clean working tree before the batch.
**Changed:** `forensics/tools/verify.py`, `forensics/tools/public_surface.py`,
`forensics/tools/tests/test_verify.py`, `forensics/tools/tests/test_public_surface.py`,
`docs/PUBLIC-VERIFIER.md`, `docs/PUBLIC-VERIFICATION.md`,
`evidence/a25/SURFACE.json`, this receipt.
**Not changed:** `src/`, `docker/`, `AGENTS.md`, `evidence/a25/INVENTORY.json`,
`evidence/a25/RECEIPT.md`, `evidence/a25/VERIFY.json`,
`evidence/a25/CONTROLS.json`, `evidence/a25/build_evidence.py`, and every other
item's records.

This batch does not commit and does not push.

The witness for every defect is re-run below against the repaired executable. The
A25 records that witnessed the *old* behaviour are left exactly as they were:
they now fail their own re-check, and that failure is recorded here rather than
removed by editing the record.

---

## 1. Environment and court

```
$ free -g
               total        used        free      shared  buff/cache   available
Mem:              45          33           6           0           6          12
Swap:             45          39           6
```

`available` is 12 GiB, below the 24 GiB floor in `AGENTS.md` §6.1, so **no build
was started**. Every command in this batch is a Python check or test and ran
inside the already-running court container, one heavy command at a time:

```
$ docker ps
openssl-rs-court	openssl-rs-court-tools:1	Up 38 hours
$ bash docker/openssl-rs-court.sh exec sh -c 'cd /work && pwd && git rev-parse HEAD'
/work
0ea00ac4d4c57cf418046b350805a059218ccd99
```

The court's cgroup cap bounds every run; nothing compiled, linked, tested or
measured on the host.

---

## 2. Files changed

Per-file totals (`git diff --numstat` at the end of the batch):

| file | added | removed |
|---|---:|---:|
| `forensics/tools/verify.py` | 157 | 41 |
| `forensics/tools/public_surface.py` | 24 | 6 |
| `forensics/tools/tests/test_verify.py` | 80 | 0 |
| `forensics/tools/tests/test_public_surface.py` | 51 | 8 |
| `docs/PUBLIC-VERIFIER.md` | 87 | 57 |
| `docs/PUBLIC-VERIFICATION.md` | 36 | 24 |
| `evidence/a25/SURFACE.json` | 35 | 19 |

Per defect (functions/sections touched; line counts are the file totals above,
because the edits interleave in `verify.py`):

| defect | files |
|---|---|
| D1 | `verify.py` (`main` dispatch, `build_parser` help/epilog, module docstring); `SURFACE.json` (`commands[list].notes`, `exitCodeProbes[list-subcommand]`, `arguments[--json]`); `PUBLIC-VERIFIER.md` §2, §2.1, §3, §9, §12; `PUBLIC-VERIFICATION.md` §2, §3; `test_verify.py` (+2 controls); `test_public_surface.py` (stub responses) |
| D2 | `verify.py` (`LISTING_SCHEMA`, `listing_rows`, `listing_document`, `render_listing`, `emit_listing`, `--json` help, docstring); `SURFACE.json` (`discovery.listJson`, `commands[list].jsonForm/jsonFields`); both documents; `test_verify.py` (+2 controls); `test_public_surface.py` (`test_two_listing_runs_are_byte_identical`, `test_the_json_fields_are_exactly_the_declared_set`, stub responses) |
| D4 | `verify.py` (`consumer_step.reads_gitignored`, `audited_private_roots`, `build_context`); `SURFACE.json` (`consumer-*/all.privateState`, `privateStateRule`); both documents; `test_verify.py` (+1 control) |
| D5 | `verify.py` (`PRIVATE_STATE_KEY/DECLARATION/INPUT_KEYS`, `run().private_state`, `deterministic_projection`, `private_state_declaration_problem`, `input_declaration_problem`, `compare_deterministic`, `render_text`); `public_surface.py` (`_projection`, private-state declaration check); `SURFACE.json` (`determinismRule`, `discovery.jsonProbe.privateStateKey/Declaration`); both documents; `test_verify.py` (+4 controls); `test_public_surface.py` (`DOCUMENT` fixture) |

No test was removed and no test was newly ignored. `test_verify.py` grew from 37
to 46 controls; `test_public_surface.py` stayed at 39.

---

## 3. Each defect

### D1 — `list` was advertised and refused

**Witness (A25 `INVENTORY.json#discrepancies[D1]`).**
`verify.py list` → exit 2, `unknown subcommand 'list'`; bare `verify.py` → exit
2, same message; source has `args.command or "list"` and no `elif name ==
"list"`.

**Old behaviour.** `--help` and the refusal message named `list`, but the
dispatch had no branch for it, so only `--list` worked. `main` defaulted a bare
invocation to the string `"list"`, which then fell through to the unknown-command
error, producing a misleading message.

**New behaviour.** `list` is a real subcommand: `verify.py list` prints the same
listing as `--list` and exits 0. A bare invocation is still refused with exit 2
(the declared contract), now with a truthful message:
`verify: no subcommand; pass a command name, `all`, or `list` (`--list` prints
the listing)`. `--list` still takes precedence over `--explain` and over a run.

**Code.** `verify.py`: `main` handles `args.command == "list"` through
`emit_listing`; the `args.command or "list"` default is replaced by an explicit
`None` refusal; the help/epilog state that discovery exits 0.

**Witness re-run.**

```
$ verify.py list
exit= 0 | head: manifest	required	in all
$ verify.py            # bare
exit= 2 | stderr: verify: no subcommand; pass a command name, `all`, or `list` (`--list` prints the listing)
```

**Document corrected.** Yes — `docs/PUBLIC-VERIFIER.md` §2 (both forms),
§2.1 (the `list` row and the bare-invocation row), §3 (a `list` → 0 probe),
§9 (D1 repaired), §12; `docs/PUBLIC-VERIFICATION.md` §2 (invocation block) and
§3 (a sentence naming `verify.py list`). Old wording preserved in §4 below.

---

### D2 — `--json` was accepted by the listing and ignored

**Witness (A25 `INVENTORY.json#discrepancies[D2]`).**
`--list --json` → exit 0 with tab-separated text, not a JSON object; the source
returns from the `if args.list:` branch before serialisation.

**Old behaviour.** The listing accepted `--json` and printed TSV anyway.

**New behaviour.** `list --json` and `--list --json` emit one JSON document,
schema `openssl-rs/verify-listing/1`, whose top-level fields are exactly
`schema`, `interface`, `commands`; each row carries `name`, `role` and `in_all`
(20 rows). The document is byte-identical between the two forms and across two
runs. `--explain`/`--help` still print text and declare no document.

**Code.** `verify.py`: `listing_rows`, `listing_document`, `render_listing`,
`emit_listing`; `main` routes both discovery forms through `emit_listing`, which
serialises with `json.dumps(..., indent=2, sort_keys=True)` when `args.json` is
set. `SURFACE.json`: `discovery.listJson` now declares `emitsJson: true`,
`format: json`, the schema and its fields; the `list` command declares
`jsonForm: document` and those fields.

**Witness re-run.**

```
$ verify.py --list --json
exit= 0 | fields= ['commands', 'interface', 'schema'] | commands= 20
$ verify.py list --json == verify.py --list --json : True
```

**Document corrected.** Yes — `docs/PUBLIC-VERIFIER.md` §2.2 (`--json` effect),
§4 (the listing document), §7 (two listing documents byte-identical), §9
(D2 repaired); `docs/PUBLIC-VERIFICATION.md` §2. Old wording in §4 below.

---

### D3 (context, unchanged)

D3 was documented rather than repaired by A25; this batch does not change the
precedence rule. The precedence still holds and is tested by the existing
`test_list_names_the_queue_subcommands` and the new subcommand control.

---

### D4 — a declared private path lay outside the audited roots

**Witness (A25 `INVENTORY.json#discrepancies[D4]`).**
The consumer commands declared `artifacts/phase2/install` in
`reads_gitignored`, while `PRIVATE_ROOTS` named `artifacts/phase2/shell`; the
document's `private_state.known_roots` therefore never contained the declared
path, so its presence could never be reported.

**Tree inspection (the decision).**

```
$ git ls-files artifacts/phase2/install | wc -l
155
$ git status --porcelain --ignored=matching -- artifacts/phase2/install
(no lines)
$ git check-ignore -v artifacts/phase2/install/lib/libcrypto.a
(no rule)
```

All 155 files under `artifacts/phase2/install` are Git-tracked, it is not
ignored by `.gitignore` or `.git/info/exclude`, and it has no untracked or
ignored entry. It is checkout content, not private state. **Decision: remove the
declaration**, rather than adding a public tracked directory to the audited set
and reporting it as private.

The defect class is also closed structurally: `audited_private_roots()` now
derives the audited set from `PRIVATE_ROOTS` **plus every `reads_gitignored` a
step declares**, so a declared private read can no longer lie outside presence
reporting.

**Old behaviour.** `--explain consumer-curl` printed
`private: court, artifacts/phase2/install`; the document audited only
`artifacts/phase2/shell`, `court`, `target` and the two authority roots.

**New behaviour.** The consumer commands declare `court` only. The audited set is
the union above; every declared read is inside it. `artifacts/phase2/install`
remains readable checkout content (the delegate's identity check) and is not
claimed to be private.

**Code.** `verify.py`: `consumer_step(reads_gitignored=("court",))`;
`audited_private_roots`; `build_context` passes the derived set to
`private_state_report`. `SURFACE.json`: `consumer-curl`/`consumer-ssh`/
`consumer-sshd.privateState = ["court"]`, `all.privateState = ["court",
"forensics/authorities/prefix"]`, `privateStateRule.knownGap = null`.

**Witness re-run.**

```
$ verify.py --explain consumer-curl | grep private
private:      court
$ verify.py authority --json | jq .private_state.known_roots (keys)
['artifacts/phase2/shell', 'court', 'forensics/authorities/downloads', 'forensics/authorities/prefix', 'target']
install present in known_roots: False
install tracked files = 155
install git status(ignored) lines = 0
every declared read audited: True  ['court', 'forensics/authorities/downloads', 'forensics/authorities/prefix']
presence today: ['artifacts/phase2/shell', 'court', 'forensics/authorities/downloads', 'forensics/authorities/prefix', 'target']
```

The presence report still works: every audited root that holds untracked or
ignored entries is listed in `present`.

**Document corrected.** Yes — `docs/PUBLIC-VERIFIER.md` §4 (`private_state`
field description), §6 (the D4 known gap replaced by the repaired rule), §9 (D4
repaired); `docs/PUBLIC-VERIFICATION.md` §4 (the audited set and the tracked
`install` path). Old wording in §4 below.

---

### D5 — live `private_state` counts inside the compared record

**Witness (A25 `INVENTORY.json#discrepancies[D5]`).**
`private_state_report` counts `git status --porcelain --ignored=matching` entries
live; the block sits at the top level and only `environment` was declared an
input, so the determinism control compared a moving observation.

**Old behaviour.** Two runs over a checkout differed in the deterministic record
if an untracked or ignored entry appeared between them; the published sentence
excluded only `environment`.

**New behaviour.** `private_state` is a declared input alongside `environment`:
it carries `declared: "private-state-input"`, `known_roots` (non-empty) and
`present`; it is required to be present, declared and populated in every run; and
it is excluded from the compared projection for the same stated reason as
`environment`. It is **not** removed from the record: a claim about private
evidence depends on it.

The determinism control still fires on a changed digest, ordering, member set,
step outcome or candidate identity, and now also on a run that omits or
mis-declares either input.

**Code.** `verify.py`: `PRIVATE_STATE_KEY`, `PRIVATE_STATE_DECLARATION`,
`INPUT_KEYS`, the declared block in `run()`, `deterministic_projection` excludes
both keys, `private_state_declaration_problem`, `input_declaration_problem`,
`compare_deterministic` checks both declarations, `render_text` marks the private
line `(recorded, not compared)`. `public_surface.py`: `_projection` accepts the
additional declared input key, and the drift detector now also refuses a document
that does not declare `private_state` as the surface declares it.
`SURFACE.json`: `discovery.jsonProbe.privateStateKey/privateStateDeclaration`,
`determinismRule` names both inputs and clears `knownGap`.

**Witness re-run** (two runs with a deliberately different `private_state`; the
probe file is ignored under `court/`, added between the runs and removed after):

```
court private_entries run1/run2: 216 217
determinism with a moved private_state: True
  OK: the deterministic record is identical across two runs; the environment is declared and
  records MemAvailable=13147222 ...; private_state is declared, audits 5 root(s) and reports 5 present
determinism when private_state is omitted: False
  E_VERIFY_DETERMINISTIC: the second run declares no 'private_state' block
```

**Document corrected.** Yes — `docs/PUBLIC-VERIFIER.md` §4 (`private_state` is a
declared input), §7 (both inputs excluded; the D5 known gap replaced), §8
(`PV_REFUSED_UNSTABLE_OUTPUT` names both inputs), §9 (D5 repaired);
`docs/PUBLIC-VERIFICATION.md` §2 and §6. Old wording in §4 below.

---

## 4. Old document wording preserved

Quoted verbatim from `HEAD` before the batch.

**`docs/PUBLIC-VERIFIER.md` §2.1 (before):**

```
| `verify.py` (no arguments) | **refused**, exit 2 |
| `verify.py list` | **refused**, exit 2 — `list` is a flag, not a subcommand |

`--json`, `--network` and `--tmp` are accepted by every form and have no effect
on `--list` or `--explain`. ...

The last two rows are defects in the executable, not parts of the contract, and
they are queued in §9. ...
```

**`docs/PUBLIC-VERIFIER.md` §4 (before):**

```
`--list` and `--explain` emit **no** JSON document: they print their text
regardless of `--json`. Their declared field set is empty, and a document
appearing where the contract says there is none is a refusal.
```

**`docs/PUBLIC-VERIFIER.md` §6 (before):**

```
**Known gap (D4).** The three consumer commands declare
`artifacts/phase2/install` as private, but the interface's audited root set names
`artifacts/phase2/shell`, so the declared path is never counted and its presence
can never be reported. The rule above is what the interface is supposed to do;
the executable does not yet do it for that one path. It is queued, not hidden.
```

**`docs/PUBLIC-VERIFIER.md` §7 (before):**

```
* the declared `environment` block is an **input to the run**, not an output: ...
  excluded from the comparison. ...
**Known gap (D5).** The top-level `private_state` entry counts are live `git
status` readings and are inside the compared record. Two runs over a checkout
are byte-identical only while the working tree is quiescent; ...
```

**`docs/PUBLIC-VERIFIER.md` §9 (before):**

```
| D1 | ... | tool defect, queued; ... |
| D2 | ... | tool defect, queued; both documents now name the exception |
| D4 | ... | tool defect, queued; stated in §6 |
| D5 | ... | tool defect, queued; stated in §7 |
```

**`docs/PUBLIC-VERIFICATION.md` §2 (before):**

```
`--json` (on a step run or on `all`; `--list` and `--explain` print their
text regardless, because they are discovery commands rather than step runs)
emits one sorted, timestamp-free document: ... The document also carries an
`environment` block ... and marks it as an environment input; the block is
recorded, not compared, and the byte-identity claim is about the rest of the
record. Two runs ... are byte-identical in everything except that declared block
and the `private_state` entry counts, which are live readings of the working
tree's untracked or ignored entries and not of the checkout (A25 D5).
```

**`docs/PUBLIC-VERIFICATION.md` §4 (before):**

```
No prerequisite is satisfied by the working tree's private state: a private path
is either declared by the step and reported as present, or absent and reported as
absent. `court/` is reported precisely ...
```

The descriptive document's subcommand-table row had already been corrected by
A25 from ``| `list` | `python3` | ...`` to ``| `--list` | `python3` | ...``;
this batch adds prose naming the `list` subcommand and leaves that row as A25
left it.

---

## 5. Committed records: what had to change and what was left alone

**Left alone, now failing their own producer.** `evidence/a25/INVENTORY.json`
and the A25 receipt/verify records witnessed the old behaviour. They are not
edited. At the repaired candidate their witnesses no longer reproduce as
recorded:

| record | old witness (verbatim expectation) | observed after the repair |
|---|---|---|
| D1 | `["list"]` → exit **2**, contains `unknown subcommand 'list'` | exit **0**, prints the listing |
| D1 | `[]` → exit **2**, contains `unknown subcommand 'list'` | exit **2**, message `no subcommand; ...` |
| D2 | `["--list","--json"]` → exit 0, TSV head `manifest\trequired\tin all`; shape “emits tab-separated text, not a JSON object” | exit 0, JSON head `{`, fields `commands/interface/schema` |
| D4 | `--explain consumer-curl` contains `artifacts/phase2/install` | the block declares `court` only |
| D5 | shape “`private_state` sits outside the declared `environment` input block” | still top-level, but now declares `private-state-input` and is excluded from the comparison |

`evidence/a25/build_evidence.py` re-checks these witnesses and would therefore
exit non-zero at this candidate. It was **not** run against the tree, because it
writes the four A25 records; that is the “finding with old and new, record left
alone” this batch is required to report.

**Had to change.**
1. `evidence/a25/SURFACE.json` — it is the declaration the gate
   (`public_surface.py verify`) compares with the executable, not an observation
   of the past. Leaving it unchanged makes the repaired executable and its own
   declaration disagree. Changes: `listJson` emits a document; `list` declares
   its document fields; the consumer/`all` private declarations drop the tracked
   `install` path; the two rule blocks name the repaired state; one probe
   (`list-subcommand`) records the repaired subcommand.
2. Four expectations in `test_public_surface.py` encoded the defects as required
   behaviour and could not survive a repair that the same task requires:
   `test_two_listing_runs_are_byte_identical` (asserted the listing is *not* a
   JSON object and contains a tab), `test_the_json_fields_are_exactly_the_declared_set`
   (assumed every document-form command shares the run document's fields),
   the `DOCUMENT` fixture (a `private_state` with no declaration), and
   `test_the_descriptive_document_no_longer_carries_the_stale_count` (a literal
   `"37 tests"` that a growing control set invalidates). Each was replaced by a
   **stronger** check, not a weaker one: the listing is parsed as a document and
   its commands are compared with the TSV rows; the listing document's fields are
   compared with what the listing actually emits; the fixture declares a
   populated private-state input; the test count is derived from the loader
   instead of a literal. Old assertions are quoted here:

```
self.assertFalse(ps._is_json_object(first.stdout),
                 "the listing is TSV; the surface declares no document here")
self.assertIn("\t", first.stdout)
...
for entry in declaration["commands"]:
    if entry["jsonForm"] == "document":
        self.assertEqual(entry["jsonFields"], declared["jsonFields"])
...
"private_state": {"present": []},
...
self.assertNotIn("19 tests", self.descriptive)
self.assertIn("37 tests", self.descriptive)
```

No test was deleted. Nothing was marked ignored.

---

## 6. Gates (exact output, run in the court)

**Gate 1 — memory and court.** See §1: `available 12` GiB, court
`openssl-rs-court` up; the tests ran in `/work` inside it.

**Gate 2 — `test_verify.py`:**

```
Ran 46 tests in 10.116s

OK
```

**Gate 3 — full tools suite:**

```
Ran 1843 tests in 422.061s

OK
closure discipline self-test: 7 control groups passed
```

1,843 = the parent's 1,834 + 9 new controls (37 → 46 in `test_verify.py`);
0 failures; none removed or newly ignored.

**Gate 4 — witnesses re-run.** D1/D2/D4/D5 outputs are in §3. The four
required invocations:

```
verify.py list          -> exit 0, TSV listing (manifest first)
verify.py               -> exit 2, "no subcommand; ..." (declared refusal)
verify.py --list --json -> exit 0, {"commands": [...], "interface": ..., "schema": ...}
D4 presence report      -> consumer declares `court`; every declared read audited;
                           install tracked=155, ignored entries=0, not in known_roots
D5 two runs, different private_state (court 216 -> 217) -> OK, identical record;
   private_state omitted from one run -> E_VERIFY_DETERMINISTIC
```

**Gate 5 — documents and surface:**

```
[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired
exit=0

spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions
exit=0

public-surface: 23 declared command(s) match the executable surface; exit codes 0, 1, 2 observed; 12 JSON field(s); 13 refusal code(s) available
public-surface: two-run determinism: listing stable; JSON document compared over 15 invocation(s)
public-surface: codes=PV_OK
exit=0
```

**Gate 6 — `git status --porcelain`:**

```
 M docs/PUBLIC-VERIFICATION.md
 M docs/PUBLIC-VERIFIER.md
 M evidence/a25/SURFACE.json
 M forensics/tools/public_surface.py
 M forensics/tools/tests/test_public_surface.py
 M forensics/tools/tests/test_verify.py
 M forensics/tools/verify.py
?? evidence/defects/d1-d5/
```

No `src/`, `docker/` or `AGENTS.md` change; no commit and no push.

---

## 7. Anything not established

* **The repaired declaration has no committed identity.** `SURFACE.json` records
  `declaredAtCommit: a9bcb5480`, the commit at which the A25 declaration was
  made; this working tree edits the declaration and cannot name the commit that
  will carry it, because the batch does not commit. Re-declaring it at the commit
  that lands this change (and re-running `public_surface.py verify` there) is a
  follow-up for the orchestrator, not evidence this batch can supply.
* **The A25 producer was not run.** `evidence/a25/build_evidence.py` writes
  `INVENTORY.json`, `SURFACE.json`, `VERIFY.json` and `CONTROLS.json`; running it
  would overwrite the declaration this batch had to update and the records it must
  leave alone. The witnesses' old-vs-new values in §5 are the direct re-runs in
  §3, not a producer transcript.
* **Independent verification is absent.** The same party wrote the repair and its
  controls. The controls and the drift detector are a finite tested set, not a
  proof (Earned Trust Articles 1, 2 and 5).
* **The listing document is new public surface.** It has its own schema
  (`openssl-rs/verify-listing/1`) and is checked against the declaration, but no
  external consumer has parsed it; the surface schema version was not bumped,
  because the run document's schema (`openssl-rs/verify/1`) is unchanged and the
  listing declares a separate schema.
* **D1's bare-invocation decision.** The batch keeps the bare invocation refused
  (exit 2), because the contract already declared that and a default command
  would make the exit status depend on a choice the caller did not make. The
  alternative reading of D1 — making bare `verify.py` print the listing — was not
  taken; if it is wanted, it is a contract change, not a repair.
* **Test expectations were changed.** Five committed controls encoded the
  defects (four assertions plus the stub fixture). They could not pass against
  the repaired executable and were updated to stronger checks with the old text
  preserved in §5. No test was deleted or ignored. This is the one place where
  the batch's instruction “do not change an expected value” and the instruction
  to repair D2 cannot both hold literally; the repair was chosen and the old
  value is recorded rather than dropped.
* **No Rust build, fmt, clippy or Miri was run.** No Rust source changed, and
  the host's available memory is below the §6.1 floor.
