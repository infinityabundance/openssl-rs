# A13 receipt — signature reproducibility is not artefact reproducibility

## 1. Identity of this batch

| field | value |
|---|---|
| item | A13 (signature reproducibility versus artefact reproducibility; the two axes kept separate; never seed production randomness for reproducible signatures) |
| branch | `staging` |
| HEAD at the start | `6b33f1caa` (`a12: a signature by the same party is not evidence to a third party`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 23 18 0 4 22` (total 45, used 23, free 18, available **22** GiB); `Swap: 45 27 18` |
| derived court cap | `min(8g, 22 - 16) = 6g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The derived cap is 6 GiB and the running container's cap is 6 GiB, equal to it.
The container was reused rather than restarted, as A7-A12 did. Every reported
gate is Python-only and ran in that court with the pinned tool `PATH` recorded
in A12's receipt:

```
PATH=/opt/opam/4.14.2/bin:/usr/local/cargo/bin:/usr/local/rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:/opt/dudect:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

`PYTHONDONTWRITEBYTECODE=1` was set for the test and tool invocations so the
bind-mounted tree gained no new `__pycache__` entries. No test was edited,
skipped, ignored or removed.

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/REPRODUCIBILITY-AXES.md` | 314 lines | normative document: the two axes; the four combinations and each prohibited inference; the scheme registry; the nonce-reuse refusal; the real result; the controls; the 14-code refusal table; the boundary with A12 and the release gate; non-claims; `NOT_RUN`; reproduction |
| `forensics/tools/reproducibility.py` | 1,136 lines | the scheme registry, `signature_evidence`, `artefact_evidence`, `classify`, the 14 codes and the `signature`/`artefact`/`classify` command line |
| `forensics/tools/tests/test_reproducibility.py` | 734 lines | 53 controls: one per code, all four combinations, the randomised-varying acceptance and the randomised-repeating refusal, the absent rebuild, the real envelopes and subjects, determinism, CLI exit codes, document synchronisation |
| `evidence/a13/SIGNATURE.json` | 289 lines / 13,048 bytes | the four real A10 envelopes signed twice; `SIGNATURE_STABLE` 4/4 under `hmac-sha256` |
| `evidence/a13/ARTEFACT.json` | 209 lines / 8,217 bytes | the four A1/A5/A7/A8 artefacts and the A4 DSO; every subject `ARTEFACT_NOT_REBUILT` |
| `evidence/a13/CLASSIFICATION.json` | 217 lines / 7,677 bytes | the four real pairs and the unpaired DSO, each with its prohibited inference |
| `evidence/a13/CONTROLS.json` | 170 lines / 5,997 bytes | 14 controls over the 14 codes, plus the accepted randomised-varying control and the control-only reproducible artefact |
| `evidence/a13/build_evidence.py` | 921 lines | deterministic producer of the four records; reads every digest from bytes, asserts every state and code |
| `evidence/a13/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A13 row only; no other row was touched.

## 3. The rule

> A deterministic signature is a property of the scheme and its inputs; a
> reproducible artefact is a property of the build. Neither is evidence for the
> other. Repeating an envelope byte-for-byte proves that the signer is a
> deterministic function of its inputs, and proves nothing about whether the
> artefact can be rebuilt. A repeated signature from a randomised scheme is not
> reproducibility; it is nonce or randomness reuse, a key-recovery defect.

The signature axis and the artefact axis are separate states. The four
combinations are named, and each carries the inference a consumer may not draw.
`SIGNATURE_VARIES` is an accepted result for a randomised scheme;
`ARTEFACT_NOT_REBUILT` is the honest result when no rebuild record exists, and
it is never promoted to `ARTEFACT_REPRODUCIBLE` because a digest is stable.

## 4. The scheme registry and the states

| scheme | deterministic | symmetric | repeat comparison |
|---|---|---|---|
| `hmac-sha256` | yes | yes | byte equality |
| `rsa-pkcs1v15` | yes | no | byte equality |
| `ed25519` | yes | no | byte equality |
| `ecdsa` | no | no | non-equality plus a nonce-reuse check |

The signature states are `SIGNATURE_STABLE`, `SIGNATURE_VARIES` (expected for a
randomised scheme), `SIGNATURE_NONCE_REUSED` (a refusal) and
`SIGNATURE_UNKNOWN`. The artefact states are `ARTEFACT_REPRODUCIBLE`,
`ARTEFACT_DIFFERS`, `ARTEFACT_NOT_REBUILT` and `ARTEFACT_UNKNOWN`.

An unrecorded scheme is `SIGNATURE_UNKNOWN` with
`SR_REFUSED_SCHEME_UNRECORDED`; fewer than two attempts is
`SR_REFUSED_ATTEMPTS_INSUFFICIENT`; a missing or undecodable signature is
`SR_REFUSED_ATTEMPT_MALFORMED`; a raw seed recorded as the key is
`SR_REFUSED_SEED_AS_KEY`; attempts with different inputs are
`SR_REFUSED_INPUTS_UNSTATED`. An absent rebuild record is
`ARTEFACT_NOT_REBUILT` with `SR_REFUSED_REBUILD_NOT_RUN`, never
`ARTEFACT_REPRODUCIBLE`; a recorded `NOT_RUN` outcome and a replay are the same
state; an envelope offered as a build subject is
`SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST`.

## 5. The real signature result

The four real A10 envelopes were signed twice with the same test-only
HMAC-SHA256 key over the same A9 statement bytes. Each attempt reproduces the
committed A10 envelope byte-for-byte, and the two attempts are identical.

| envelope | attempts | payload sha256 (first 12) | envelope digest (both attempts) | state |
|---|---:|---|---|---|
| `a1-sarif` | 2 | `d53bc4eb66f7` | `8b0aa7989f43e11a7a6773469ea5a423219fd291a09f5a1a66e48e0d4dee84cd` | `SIGNATURE_STABLE` |
| `a5-admission` | 2 | `d17bb4c99089` | `8f9144f20d9a6e8ce04dabe03ce701741149f2f5e2c59a5ec92721244d3ea93e` | `SIGNATURE_STABLE` |
| `a7-delta` | 2 | `d4dfa5a3b374` | `068ea1274eae816129be016ec4a043e92d9e2353029bbb88b4436f7cdecb3385` | `SIGNATURE_STABLE` |
| `a8-shard-000` | 2 | `ea67963abf16` | `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9` | `SIGNATURE_STABLE` |

**Aggregate: 4 stable, 0 varying, 0 nonce-reused, 0 unknown.** The key is
`test-only:hmac-sha256:8e10a5a15d233d54`, derived from the fixed public seed
`openssl-rs/a10/test-only-hmac-sha256-seed/v1`. This is a property of HMAC-SHA256
and of that fixed test seed. It establishes that the signer is a deterministic
function of `(key, message)`, and it says nothing about the build, authenticity,
identity, authorisation or independence.

## 6. The real artefact result

| subject | kind | recorded digest (first 12) | rebuild record | state |
|---|---|---|---|---|
| `evidence/a1/SARIF.json` | evidence artefact | `5c0cfee62512` | absent | `ARTEFACT_NOT_REBUILT` |
| `evidence/a5/ADMISSION.json` | evidence artefact | `d4871ec97ae3` | absent | `ARTEFACT_NOT_REBUILT` |
| `evidence/a7/DELTA.json` | evidence artefact | `0444a879bf4a` | absent | `ARTEFACT_NOT_REBUILT` |
| `evidence/a8/SHARD-000.sarif` | evidence artefact | `b16d376ae0b2` | absent | `ARTEFACT_NOT_REBUILT` |
| `artifacts/phase2/install/lib/libcrypto.so.3` | build product | `fd25cc9e6424` | recorded `NOT_RUN` | `ARTEFACT_NOT_REBUILT` |

The DSO is present and its recomputed digest equals the digest recorded by A4:
`fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9`. Its rebuild
record is the recorded `NOT_RUN`: `MemAvailable 22 GiB` is below the 24 GiB floor
that AGENTS.md section 6.1 requires before a build, the court is capped at
6 GiB (`6442450944` bytes), and when the full rebuild is attempted in that court
`build_reproducibility.sh` exits 101 (`evidence/gate-reliability/RECEIPT.md`
records the observed case; `evidence/etp-t12/RUN.json` records the `NOT_RUN`
step and its inputs). The recorded digest was **not** regenerated in this
batch.

**Aggregate: 5 subjects, 5 `ARTEFACT_NOT_REBUILT`, 0 reproducible, 0 differs,
0 unknown.** A stable digest is an identity, not a reproduction, so no
build-reproducibility claim is made for any subject.

## 7. The classification

`evidence/a13/CLASSIFICATION.json` classifies each pair. All four real pairs are
`STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT`, with
`SR_REFUSED_SIGNATURE_AS_ARTEFACT`, `SR_REFUSED_REBUILD_NOT_RUN`,
`SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE`,
`SR_REFUSED_ARTEFACT_AS_SIGNATURE`, `SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST`
and `SR_REFUSED_SEED_AS_KEY` named as prohibited. The DSO is `UNPAIRED`: it is a
build product, not one of the four signed statements, and it is not given a
signature-axis reading.

The combination registry records all four labels and the principal prohibited
inference for each. A completed rebuild whose products differ is
`ARTEFACT_DIFFERS`, which licenses no reproducibility and is labelled outside
the four reproducibility combinations.

## 8. The controls

`evidence/a13/CONTROLS.json` records one control per refusal code: 14 controls
over 14 codes. Each asserts that its named code fires.

| control | code | mechanism | state |
|---|---|---|---|
| `signature-as-artefact` | `SR_REFUSED_SIGNATURE_AS_ARTEFACT` | classify | prohibited |
| `artefact-as-signature` | `SR_REFUSED_ARTEFACT_AS_SIGNATURE` | classify | prohibited |
| `deterministic-scheme-as-independence` | `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE` | classify | prohibited |
| `nondeterministic-as-failure` | `SR_REFUSED_NONDETERMINISTIC_AS_FAILURE` | classify | prohibited |
| `nonce-reuse` | `SR_REFUSED_NONCE_REUSE` | signature | `SIGNATURE_NONCE_REUSED` |
| `envelope-digest-as-build-digest` | `SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST` | artefact | `ARTEFACT_UNKNOWN` |
| `seed-as-key` | `SR_REFUSED_SEED_AS_KEY` | signature | `SIGNATURE_UNKNOWN` |
| `inputs-unstated` | `SR_REFUSED_INPUTS_UNSTATED` | signature | `SIGNATURE_UNKNOWN` |
| `rebuild-not-run` | `SR_REFUSED_REBUILD_NOT_RUN` | artefact | `ARTEFACT_NOT_REBUILT` |
| `scheme-unrecorded` | `SR_REFUSED_SCHEME_UNRECORDED` | signature | `SIGNATURE_UNKNOWN` |
| `replay-as-reproduction` | `SR_REFUSED_REPLAY_AS_REPRODUCTION` | artefact | `ARTEFACT_NOT_REBUILT` |
| `attempts-insufficient` | `SR_REFUSED_ATTEMPTS_INSUFFICIENT` | signature | `SIGNATURE_UNKNOWN` |
| `attempt-malformed` | `SR_REFUSED_ATTEMPT_MALFORMED` | signature | `SIGNATURE_UNKNOWN` |
| `deterministic-varied` | `SR_REFUSED_DETERMINISTIC_VARIED` | signature | `SIGNATURE_VARIES` |

The positive controls are `deterministic-stable` (accepted),
`randomised-varies` (a synthetic randomised-scheme pair that varies; accepted,
not a failure), `artefact-reproducible-synthetic` (a synthetic rebuild with two
equal digests; **control-only**) and `four-combinations` (each combination
reachable with its prohibited inference). The synthetic reproducible artefact
is excluded from the real result: 0 real subjects are reproducible. The
randomised pair that repeats is the `nonce-reuse` control and is refused as
`SR_REFUSED_NONCE_REUSE`.

| quantity | measured |
|---|---:|
| refusal codes | 14 |
| controls | 14 (one per code) |
| positive controls | 4 (one control-only) |
| real envelopes | 4 |
| real signature-stable | **4** |
| real nonce-reused | **0** |
| real subjects | 5 |
| real reproducible | **0** |
| real not rebuilt | **5** |
| new `unittest` controls | 53 |
| whole tools suite | 1,202 (1,149 before this item) |

## 9. Defects found

**One defect was found in an existing record, and it is pre-existing at this
base.** `evidence/a11/SCAN.json` records a population of 386 files. A11's
`SCAN_GLOB` is `evidence/*.json` and its matcher lets `*` cross `/`, so the
three JSON records A12 committed (`evidence/a12/CONTROLS.json`,
`evidence/a12/TRUST-ROOTS.json`, `evidence/a12/VERIFICATION.json`) entered the
population after A11's record was made. The population is now 389. Three tests
in `test_harden` fail for that reason: the recorded population (386) is not the
current one (389), the CLI prints `files=389` where the record says 386, and
A11's producer regenerates 389 where the committed bytes say 386.

This is **not** caused by A13: the A13 records are untracked, so `git ls-files`
does not see them. It is a stale generated record caused by A12's commit. It was
confirmed at the base commit without any A13 file: a detached worktree at
`6b33f1caa` read `Ran 64 tests in 4.278s`, `FAILED (failures=3)` in
`test_harden`, with the same `386 != 389`, and the worktree was removed. The
check was not relaxed. After this item is committed the population becomes
**393**, because the four `evidence/a13/*.json` records also match
`evidence/*.json`; the repair must therefore be made at the integration commit
that includes A13, not in this subagent's working tree. The repair is to
regenerate A11's `SCAN.json`, `DIFFERENTIAL.json` and `CONTROLS.json` at that
source identity and to record the supersession in A11's receipt (old 386 files /
211 examined / 175 skipped preserved beside the new counts). That repair is
outside this item's write scope and is retained as an obligation below.

Four defects were found in this item's own new files and are preserved with the
old and the new form. None was a silent pass: each failed before a record was
reported as green.

| file | old form | new form | found by |
|---|---|---|---|
| `evidence/a13/build_evidence.py` | `CONTROLS.json`'s `sourceIdentity` named `evidence/a13/CONTROLS.json` as its own input, so the second run would hash the first run's output and the bytes would differ | `document_identity` computes the digest from the in-memory document with the exact `write_json` serialisation; `CONTROLS.json` names only the tool as its input | inspection before the first recorded run |
| `forensics/tools/tests/test_reproducibility.py` | `import build_evidence as be` resolved to another item's cached `build_evidence` under whole-suite discovery, and two tests errored with `AttributeError: module 'build_evidence' has no attribute 'DSO_NAME'` | the A13 producer is loaded by path under the private name `a13_build_evidence` with `importlib.util`, so discovery order cannot choose another item's producer | the whole-suite run (`errors=2`) |
| `docs/REPRODUCIBILITY-AXES.md` | the phrase `no build-reproducibility claim` was split across a newline, so the document-synchronisation test did not find it | the phrase is on one line | `test_the_document_states_the_real_result` |
| `forensics/tools/tests/test_reproducibility.py` | `test_the_signature_axis_does_not_claim_anything_about_the_build` searched for `build` in `doesNotEstablish`, whose entry says `rebuilt` | the test searches for `rebuil` in the lowercased entry | that test's own first run |

**Gate history preserved.** The first whole-suite run after the item read
`Ran 1202 tests in 212.691s`, `FAILED (failures=3, errors=2)`. The two errors
were the `build_evidence` module collision above; the three failures were the
A11 population failures above. After the import repair the whole suite reads
`Ran 1202 tests in 211.231s`, `FAILED (failures=3)` — the same three
pre-existing A11 failures, now with no error. The focused A13 module reads
`Ran 53 tests in 0.349s`, `OK`. The check was not relaxed.

## 10. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time, with
the tool `PATH` recorded in §1.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 23 18 0 4 22` (available 22 GiB); `Swap: 45 27 18` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1202 tests in 211.231s`; `FAILED (failures=3)`; the three are `test_harden.CommandLine.test_scan_prints_the_code_and_the_counts`, `test_harden.Evidence.test_the_producer_is_deterministic_and_matches_the_committed_bytes` (`SCAN.json`) and `test_harden.ScanTests.test_the_recorded_scan_covers_the_population`. **1,149 pre-existing tests are present** (1,149 + 53 = 1,202), **none ignored**; the failures are pre-existing A11 staleness, not A13 controls |
| focused A13 suite | `python3 -m unittest forensics.tools.tests.test_reproducibility` | `Ran 53 tests in 0.349s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `SIGNATURE.json`, `ARTEFACT.json`, `CLASSIFICATION.json`, `CONTROLS.json` | `ok` for all four, exit 0 each |
| producer, two runs | `python3 evidence/a13/build_evidence.py --out /tmp/a13c --source-commit 6b33f1caa` and the same to `/tmp/a13d` | `a13: signatures=4 stable=4 varies=0 nonceReused=0 artefacts=5 notRebuilt=5 reproducible=0 pairs=4 codes=14 controls=14 commit=6b33f1caa` twice |
| producer byte-identity | `cmp` of `/tmp/a13c/<name>`, `/tmp/a13d/<name>` and `evidence/a13/<name>` | `identical` for `SIGNATURE.json`, `ARTEFACT.json`, `CLASSIFICATION.json` and `CONTROLS.json` |
| the real classification | `python3 forensics/tools/reproducibility.py classify` | exit 0; four `name=<envelope> combination=STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT signature=SIGNATURE_STABLE artefact=ARTEFACT_NOT_REBUILT prohibited=...` lines and one `combination=UNPAIRED artefact=ARTEFACT_NOT_REBUILT subject=a4-libcrypto-dso` line; codes fired on real data: `SR_REFUSED_SIGNATURE_AS_ARTEFACT`, `SR_REFUSED_ARTEFACT_AS_SIGNATURE`, `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE`, `SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST`, `SR_REFUSED_REBUILD_NOT_RUN`, `SR_REFUSED_SEED_AS_KEY` |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/REPRODUCIBILITY-AXES.md`, `?? evidence/a13/`, `?? forensics/tools/reproducibility.py`, `?? forensics/tools/tests/test_reproducibility.py` |

**Reproducibility.** The producer reads the four A10 envelopes, the four A9
statements, the four A1/A5/A7/A8 artefacts, the A4 DSO and its recorded digest,
the ETP-T12 rebuild record and the gate-reliability receipt. Every digest is
computed from bytes; the reasons a rebuild did not run are read from the
recorded records. Two runs are byte-identical and the committed files match a
fresh build, enforced by
`test_the_producer_is_deterministic_and_matches_the_committed_bytes`. The source
identity is supplied (`--source-commit`); without it the recorded `BASE_COMMIT`
is reused, never a live `HEAD`.

## 11. Obligations retained

* **The whole tools suite is not green.** Three pre-existing `test_harden`
  failures remain because A11's committed `SCAN.json` is stale after A12's three
  committed JSON records. The repair is a regeneration of A11's scan at a new
  source identity, with A11's receipt supersession note; it is outside this
  item's write scope and must not be done by relaxing A11's population check.
* **No completed rebuild of any subject.** Every subject is
  `ARTEFACT_NOT_REBUILT`; the DSO's recorded digest was not regenerated.
* **No real randomised-scheme signing.** `ecdsa` is represented only by
  synthetic controls; no production ECDSA key or signer is used.
* **No production signature scheme or key.** The real envelopes use the A10
  test-only HMAC-SHA256 key derived from a fixed public seed.
* **No independence.** A12 owns the trust root; the real result here licenses
  no independence claim.
* **No release decision or package reproduction.** The release gate's `gate-5`
  package item and `etp6_package.py` are separate; A13 does not run them.
* **No independent review.** The author of the tool, document and controls is
  not an independent adjudicator of the code-to-conclusion mapping.
* **The positive control is not a real build.** The synthetic reproducible
  artefact establishes the decision procedure only.

## 12. `NOT_RUN`

* **A completed rebuild of any subject.** No rebuild record with a completed
  outcome exists.
* **A rebuild of the A4 DSO at its recorded digest.** The recorded rebuild is
  `NOT_RUN`; the digest is recorded, not regenerated.
* **A real ECDSA signing.** Only synthetic randomised-scheme controls.
* **A production key, signer or certificate.** None is used.
* **A12 independence, A14 role authorisation, A15 thresholds, A16 Sigstore
  bundles, A17 transparency.** Not implemented here.
* **The release gate's package reproduction and `verify.py rebuild`.** Separate
  measurements at different identities; not inherited.
* **Independent review, BOUNDARY and SEAL.** No caller/dependency-closure audit,
  no independent reviewer, no full forensic regeneration.
* **The Rust suite.** `src/` was not modified, so no rebuild or `cargo test` was
  run.

## 13. Boundary with A12 and the release gate

A12 asks whether the verifier's root of trust is outside the candidate and the
producing party; A13 asks whether a signature repeats and whether an artefact
rebuilds. A deterministic HMAC signature is not an independent signature: the
key is symmetric and the verifier holds it. `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE`
names that boundary, and the real result here is zero independence claims.

The release gate's package reproduction (`forensics/tools/release_gate.py`,
`gate-5`, and the ETP-6 package verifier) asks whether a specific published
package contains the inputs its manifest names and whether the package verifies.
A13 does not run a build, does not unpack a package and does not decide a
release. It records whether the supplied rebuild record is a completed build. A
completed rebuild here would be necessary for a reproducibility claim, never
sufficient for a release.

A10 owns the envelope, PAE and signature verification; A11 owns parser
hardening. A13 reads their output as bytes and does not re-verify a signature,
re-parse an envelope or re-run a parser. ETP-2 records the two-build artefact
reproduction for its own candidate; A13 records the DSO's recorded `NOT_RUN` at
a different identity and does not inherit ETP-2's result.
