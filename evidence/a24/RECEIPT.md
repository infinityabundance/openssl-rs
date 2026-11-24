# A24 receipt — a package an outsider could run, and the honest status that none has

## 1. Identity of this batch

| field | value |
|---|---|
| item | A24 (external verification package: a self-contained bundle of the verifier and its frozen inputs that a third party can run offline, with no private state, no network and no toolchain beyond the declared interpreter) |
| branch | `staging` |
| HEAD at the start | `b19869e224d2610656bbc22321d4734b21875dae` (`a23: write the rules down, then check the code against them`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 32 8 0 5 13` (total 45, used 32, free 8, available **13** GiB); `Swap: 45 38 7` |
| `free -g` before the suite | `Mem: 45 33 7 0 5 12` (available **12** GiB); `Swap: 45 38 7` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), repository at `/work`; reused, not restarted |
| interpreter in the court | Python **3.11.2**, the declared minimum the package names |
| heavy commands | one at a time; no Rust build |

The host had 13 GiB available before the work and 12 GiB before the suite, below
the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed —
every gate is Python — and the derived cap `min(8, available − 16)` is below the
2 GiB floor in both cases, so **no new court was started**. The already-running
court with its hard 6 GiB cap was reused, and every command that reads or runs
the tree ran inside it. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/package_external.py` | 1,417 | `build`, `verify`, `inventory`; the structural scans, the stripped-environment runner, the audit driver, the 12 refusal codes and the four outcomes; CLI exit 0/1/2 |
| `forensics/tools/tests/test_package_external.py` | 750 | 64 controls: one per refusal code, the stripped-environment rule observed from inside the entry point, a run from a temporary directory, two-run reproducibility, manifest and mutation detection, the entry point checking its own manifest, a direct run writing nothing into the package, the structural no-network scan, the external status never verified, determinism, CLI exit codes, document synchronisation |
| `docs/EXTERNAL-PACKAGE.md` | 371 | the normative document: the problem, the package contract, the stripped-environment rule, the no-network/no-private-state structural tests, the exclusion rule, the real package and its in-venue run, the external status, the refusal table, the A12/A17 boundary, non-claims, `NOT_RUN` |
| `evidence/a24/build_evidence.py` | 585 | deterministic producer: builds the package, verifies it in this venue, writes `RUN.json`, `STATUS.json`, `CONTROLS.json`, exits nonzero on any disagreement |
| `evidence/a24/RUN.json` | 116 | the in-venue run: stripped environment, commands, exit status, 4 records compared, `PACKAGE_VERIFIED_IN_VENUE`, `EXTERNAL_REVIEW_PENDING`, `notExternal: true`, and the verifier/producer digests |
| `evidence/a24/STATUS.json` | 37 | `EXTERNAL_REVIEW_PENDING`, `externalPartyRan: false`, `isPass: false`, what would count as external reproduction, what the external party must publish |
| `evidence/a24/CONTROLS.json` | 172 | 16 `controlOnly` controls covering all 12 refusal codes plus the positive real-package control; every row observed its declared code |
| `evidence/a24/PACKAGE/` | 15 members + manifest | the package directory plus `PACKAGE-MANIFEST.json` (16 files); text only, no archive |
| `docs/ETP-TODO.md` | 1 row | the A24 row replaced from `TODO` to `DONE`, stating `EXTERNAL_REVIEW_PENDING` plainly; no other row touched |
| `evidence/a24/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `package_external.py` | `31a44e5cdce42b9eb6280b491fd286989a8135a505e1738d3a449d4e8caed930` |
| `test_package_external.py` | `34569c4b5d68d4ab895abd8bd96603d640d3ece6e96795571cd1b45b27cad853` |
| `build_evidence.py` | `c1bc880374eca1461a6fa1600ddae4f35f6576ed3af0f5c5ca84696b3889fc25` |
| `EXTERNAL-PACKAGE.md` | `aa0bb44e260a4316b575180fc4a9e8473d40f586c5ed498fab1bbbe52bbee4d8` |
| `RUN.json` | `d0c8d318c6d0ae77f33f550b44e082a1ccecb08af5ddc81cb28b9e51688f3a05` |
| `STATUS.json` | `19216b89689601d7a7a48fc1e68cef06f679fb2fe853400172f7925984e2bb02` |
| `CONTROLS.json` | `9ab2b522443df3a26ae31fda70a758a17e7b11f310719a589dc0d53f45d1e0ba` |
| `PACKAGE/PACKAGE-MANIFEST.json` | `fbe65f5148d50ba601598b5dab3d59ed046ecee6abd495003d60438452fd2c7f` |

Package digest (over the manifest body): `d74ff6c9dff30acc7f854141d7639a575f07a097eaddf88856083a9ada7f61d6`.

## 3. The rule

> **An in-venue reproduction is not external evidence.** A package is a claim
> that *these files alone*, run by *this interpreter* in *a stripped
> environment*, reproduce *these records*; it is refused when any input is
> outside the declared set, names private state, imports a network client or
> program, or is untracked. And even a passing in-venue run is only a
> self-reproduction: `EXTERNAL_REVIEW_PENDING` is the honest status until a
> party in a distinct trust domain publishes its own signed verdict (Earned
> Trust Articles 1, 2 and 5).

The package contract is `PACKAGE-MANIFEST.json`: members by path, size and
SHA-256; the entry point; the minimum interpreter; the exact commands; the
declarations `network: false` and `privateState: none`; the exclusion rule and
the excluded list; the refusal codes; and the manifest's own digest.

**The exclusion rule:** a file is packaged only when every input it reads is in
the package and every program it executes is the declared Python interpreter. A
file that needs the court, the Rust toolchain, a C compiler, binutils, a shell
script, a network service or private state is excluded and named with the
reason it cannot run offline.

## 4. The package, what was excluded, the in-venue run, the external status

**Contents (15 members: 11 declared inputs plus 4 generated files).**
`forensics/tools/verifier_formalisation.py` and its five implementation-adapter
modules (`policy_engine.py`, `thresholds.py`, `authorisation.py`,
`corrections.py`, `dsse.py`); `evidence/a23/build_evidence.py`;
`evidence/a23/SPEC.json`; the expected `DIFFERENTIAL.json`, `PROPERTIES.json`
and `CONTROLS.json`; and the generated `verify.py`, `verify.sh`, `README.md`,
`PIPELINE.json`. The entry point runs the A23 producer with `-I -S -B`, which
recomputes the specification digest, the four differential domains (75,607
compared cases), the seven invariants and the ten controls, and compares four
produced records byte-for-byte with the packaged expected records.

**Excluded, with the rule.** `forensics/tools/adversarial_qualification.py` and
its E1–E3 fixtures were considered and excluded: the E1/E2 harnesses execute
`courts/phase18/timing/binsec_checkct.sh` under `bash` and call `compile_elf`,
the E3 harness calls `require_tool("objdump")` and `compile_asm`, and both
compile helpers call `require_tool("cc")`. They do not run on constructed inputs
alone; a package containing them would depend on a shell, a C compiler and
binutils. The same R1 rule excludes `courts/phase18/timing/*`, the E4 timing
harness and its recorded receipt, and `forensics/tools/etp6_package.py`; R2
excludes evidence no packaged verifier reads; R3 excludes `docker/`; R4
excludes `src/`. The manifest's `excluded` array names each with its rule and
reason.

**In-venue run.** `evidence/a24/RUN.json` records `python3
forensics/tools/package_external.py verify evidence/a24/PACKAGE`: the package was
copied into two fresh temporary directories, the entry point ran twice with a
stripped environment (`PATH` one entry, no `PYTHONPATH`, no inherited variable,
fresh `HOME`/`TMPDIR`, fresh interpreter isolated with `-I -S -B`), the audit
hook observed **0 reads outside the package**, **4 records** were compared and
all were byte-identical, and the outcome was `PACKAGE_VERIFIED_IN_VENUE` on
interpreter 3.11.2 against the declared minimum 3.11. The record names the
verifier (`forensics/tools/package_external.py`) and the producer
(`evidence/a24/build_evidence.py`) by digest, and says `notExternal: true`,
`externalPartyRan: false`, `isExternal: false`.

**External status.** `EXTERNAL_REVIEW_PENDING`. **No external party has run this
package.** The in-venue run is a self-reproduction and is not presented as
external reproduction. A claimed external run is refused with
`EV_REFUSED_EXTERNAL_NOT_RUN`; no code path upgrades the status.

## 5. The controls

`evidence/a24/CONTROLS.json` holds 16 `controlOnly` rows. Each constructs the
input its code must refuse and records the observed code; all observed their
declared code.

| control | code observed |
|---|---|
| `private-state-reference` | `EV_REFUSED_PRIVATE_STATE` |
| `missing-build-input` | `EV_REFUSED_MISSING_INPUT` |
| `absolute-path-input` | `EV_REFUSED_ABSOLUTE_PATH` |
| `network-import` | `EV_REFUSED_NETWORK` |
| `subprocess-import` | `EV_REFUSED_UNDECLARED_TOOL` |
| `outside-package-read` | `EV_REFUSED_UNDECLARED_DEPENDENCY` |
| `undeclared-build-path` | `EV_REFUSED_UNDECLARED_DEPENDENCY` |
| `member-digest-mismatch` | `EV_REFUSED_MANIFEST_MISMATCH` |
| `produced-record-mismatch` | `EV_REFUSED_MANIFEST_MISMATCH` |
| `non-reproducible-entrypoint` | `EV_REFUSED_REPRODUCIBLE` |
| `untracked-input` | `EV_REFUSED_UNTRACKED_INPUT` |
| `whole-package-mutation` | `EV_REFUSED_PACKAGE_MUTATED` |
| `manifest-body-tamper` | `EV_REFUSED_PACKAGE_MUTATED` |
| `claimed-external-run` | `EV_REFUSED_EXTERNAL_NOT_RUN` |
| `failing-entrypoint` | `EV_REFUSED_ENTRYPOINT_FAILED` |
| `real-package-verified` | `EV_OK` (positive control) |

`codesCovered` is the 12 refusal codes; `coversEveryCode: true`. The positive
control is named separately (`positiveControl: real-package-verified`), so
`EV_OK` is not counted as a refusal code.

## 6. Defects found

**The run-time network check was too broad, and the minimum-interpreter run found
it.** The first in-venue attempt in the court (Python 3.11.2) refused with
`EV_REFUSED_NETWORK`: `run 1 loaded 'urllib'`. Python 3.11's `pathlib` imports
`urllib.parse`, which is string parsing, not a network client. Old: the
run-time set was the `urllib` root package. New: the run-time set names exact
client modules (`urllib.request`, `http.client`, `socket`, `ssl`, …), while the
static scan still refuses any `import urllib`. This narrows the *observation*;
it does not relax the rule, and the static guard was not changed. Preserved in
this section and in `package_external.py`'s `_AUDIT_DRIVER`.

**The controls' coverage counter counted the success code.** The first control
run reported `codesCovered` with 13 entries including `EV_OK`, so
`coversEveryCode` was `false` even though all 12 refusal codes were covered.
Old: coverage compared the union of expected codes, success included. New:
coverage is the intersection with the 12 refusal codes, and the positive
control is recorded in its own field. The check was corrected, not relaxed.

**A test fixture embedded a real newline in a bytes literal.** The first version
of `_MINI_ENTRY_ENVIRONMENT` wrote `b"{}` followed by a newline, so the member
did not parse and the scan refused it (`EV_REFUSED_UNDECLARED_TOOL`). Old: a
fixture that is not a valid Python member. New: `b"{}" + bytes([10])`, which is
the same bytes and parses. No production code changed.

**The entry point checked a manifest that the unpacked copy did not contain.**
The first version of the self-checking entry point refused every run with
`EV_REFUSED_MISSING_INPUT`, because `verify(package_dir)` unpacked only the
declared members and not `PACKAGE-MANIFEST.json`, so the entry could not find the
manifest it was asked to check. The producer reported it as
`EV_REFUSED_ENTRYPOINT_FAILED` (`run 1 exited 0 (entry 1)`), not as a pass. Old:
an unpacked package without its manifest. New: `_unpack` copies the manifest
together with the members. The check was not removed or weakened, and
`test_the_entry_point_checks_the_manifest` now tampers a member and requires the
entry point to refuse it.

**The audit allowlist was wider than the claim.** The first version allowed
every path under the interpreter prefix and the site-package directories, so a
read of any system file under them would not have been recorded. Old: an
allowlist that included `sys.prefix`, `sys.base_prefix` and `purelib`/`platlib`.
New: the package, the temporary run root, the interpreter's own directory and
the `stdlib`/`platstdlib` paths only. A read of a site-package or arbitrary
prefix file is now `EV_REFUSED_UNDECLARED_DEPENDENCY`. The tightened check was
re-run and the package still passes.

**A direct `python3 verify.py` wrote bytecode into the package, mutating it.**
The documented command is `python3 verify.py`, and the first shell-wrapper run was
made without `-B`; the producer's imports wrote
`forensics/tools/__pycache__/*.pyc` into the package directory, so a recipient's
first run would change the package it was verifying. Old: the entry point relied
on the caller passing `-B`, and the wrapper did not. New: `verify.py` sets
`sys.dont_write_bytecode = True` before it imports the packaged modules, and
`verify.sh` passes `-B` as well. `test_a_direct_run_writes_nothing_into_the_package`
runs the entry point without `-B` and requires no `__pycache__` and no `.pyc`.
The polluted directory was rebuilt rather than edited, so the delivered package
digest is the clean one.

**No defect in an existing record was rejected by a gate.** `docs_consistency.py`
and `spec_guard.py` passed unchanged; no expected value was changed, no check
was relaxed, and no other item's tool or evidence was modified. The exclusion of
A22 E1–E3 is a recorded scope decision (it needs `cc`, `objdump` and `bash`), not
a defect in A22.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 32 8 0 5 13` (available 13 GiB); `Swap: 45 38 7` |
| memory before the suite | `free -g` (host) | `Mem: 45 33 7 0 5 12` (available 12 GiB); `Swap: 45 38 7` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1795 tests in 412.312s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,731 pre-existing tests are present (1,731 + 64), none removed, none ignored |
| focused A24 controls | `python3 -m unittest forensics.tools.tests.test_package_external` | `Ran 64 tests in 69.764s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `RUN.json`, `STATUS.json`, `CONTROLS.json`, `PACKAGE/PACKAGE-MANIFEST.json`, `PACKAGE/PIPELINE.json` | `json.tool ok` for all five |
| producer, two runs | `python3 evidence/a24/build_evidence.py` twice in the court | both: `a24: base=b19869e22 members=15 package=d74ff6c9dff30acc7f854141d7639a575f07a097eaddf88856083a9ada7f61d6 records=4 runs=2 outcome=PACKAGE_VERIFIED_IN_VENUE controls=16 codesCovered=12 failing=0 codes=EV_OK external=EXTERNAL_REVIEW_PENDING`, exit 0 |
| producer byte-identity | `sha256sum` over `evidence/a24` before, after run 1, after run 2 | `diff` before vs run 1: `identical`; run 1 vs run 2: `identical` |
| package verify | `python3 forensics/tools/package_external.py verify evidence/a24/PACKAGE` | `package-external: 4 record(s) compared, 2 run(s), interpreter 3.11.2`; `package-external: code=EV_OK outcome=PACKAGE_VERIFIED_IN_VENUE external=EXTERNAL_REVIEW_PENDING`; exit 0. **No refusal code fired** |
| entry point through the shell wrapper | `env -i PATH=/usr/bin:/bin HOME=<fresh> TMPDIR=<fresh> sh evidence/a24/PACKAGE/verify.sh` | `{"code": "EV_OK", "externalStatus": "EXTERNAL_REVIEW_PENDING", "outcome": "PACKAGE_VERIFIED_IN_VENUE", "producerExit": 0, "records": [... four `"equal": true` ...]}`, exit 0 |
| package inventory | `python3 forensics/tools/package_external.py inventory evidence/a24/PACKAGE` | `package-external: 15 member(s), entry verify.py, interpreter >= 3.11`; `code=EV_OK outcome=PACKAGE_UNVERIFIED external=EXTERNAL_REVIEW_PENDING`; exit 0 |
| worktree | `git --no-pager status --porcelain` | see §10 |

## 8. Obligations retained

* **External reproduction remains outstanding.** No party outside this project
  has run the package; `EXTERNAL_REVIEW_PENDING` is the status and not a pass.
* **The package digest is not a signature.** It detects accidental or casual
  change; a rewritten package with a recomputed digest is not detected. An
  authenticated delivery channel is not supplied.
* **The static scan is not a sandbox.** It refuses named imports, calls and
  private-state markers; it cannot prove the absence of a computed network call.
  The audit hook is one run's observation, not a general sandbox.
* **The declared minimum is tested only at 3.11.2**, the interpreter recorded in
  `RUN.json`. Other interpreters, architectures and operating systems were not
  run.
* **A23's own limits are inherited.** The packaged differential is over finite
  declared domains (only `decision-policy` is a whole state space), the
  reference shares an author with the implementation, and no machine-checked
  proof exists. A24 packages A23; it does not re-establish it.
* **Evidence identity.** Every record names base `b19869e22`, the package digest
  and the four record digests. An edit to a packaged member or to the A23
  records invalidates the run until the producer is re-run.

## 9. `NOT_RUN`

* An external run, an independent trust domain, and any A12-style verification
  of the package.
* An A17 freeze and reconciliation over this package, and any signed closure of
  it; `evidence/a17/FREEZE-forward.json` was not amended.
* Execution on any interpreter other than 3.11.2, on another architecture, or
  on another operating system.
* An authenticated delivery channel (publication, transparency log, timestamp).
* The rest of the A24 queue row's wider surface: frozen claim-set manifest,
  full SARIF, native evidence, reconciliation, envelopes, in-toto statements,
  Sigstore bundles, release policy and its controls.
* A proof that the package contains no defective code, and a sandboxed execution
  of untrusted package content.
* A BOUNDARY audit, a SEAL, and the Rust test suite — no Rust source was
  modified.

## 10. Forward-freeze member and worktree

`evidence/a17/FREEZE-forward.json` declares **one** A24 member:

* **satisfied:** `a24-receipt` — `evidence/a24/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

The freeze remains `state: OPEN`; it was not amended and not closed, and this
receipt does not claim any other member.

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
?? docs/EXTERNAL-PACKAGE.md
?? evidence/a24/
?? forensics/tools/package_external.py
?? forensics/tools/tests/test_package_external.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row (A24).
