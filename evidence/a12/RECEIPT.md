# A12 receipt — independent verification, and the root of trust outside the candidate

## 1. Identity of this batch

| field | value |
|---|---|
| item | A12 (independent cryptographic verification of envelopes: the root of trust must not be the candidate; no verification dependency in `libcrypto`/`libssl`) |
| branch | `staging` |
| HEAD at the start | `1d571da35` (`a11: a permissive parse is not a reading`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 23 18 0 4 22` (total 45, used 23, free 18, available **22** GiB); `Swap: 45 27 18` |
| derived court cap | `min(8g, 22 − 16) = 6g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The derived cap was 6 GiB and the running container's cap is 6 GiB, equal to it.
The container was reused rather than restarted, as A7–A11 did: one court holds
the memory budget, and restarting it would not lower the cap. Every reported gate
is Python-only and ran in that court. `free -g` after the work read
`Mem: 45 23 18 0 4 22` (available 22 GiB).

**Court environment, recorded because it mattered.** A first whole-suite run used `sh -lc`; the login-shell profile reset `PATH` so the pinned toolchain and BINSEC were not found, and 12 pre-existing tests in `test_binary_assurance` and `test_instrument_qualify` failed (`rustc`/`cargo`/`binsec` not found, and a live TCB `cargo` digest resolved to the toolchain binary rather than the rustup shim). The gates below use `sh -c` with the image's intended tool paths
plus the pinned toolchain bin:

```
PATH=/opt/opam/4.14.2/bin:/usr/local/cargo/bin:/usr/local/rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:/opt/dudect:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

With that `PATH` the same modules pass and the whole suite is green. No test was
edited, skipped, ignored or removed; the environment was corrected, not the check.

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/INDEPENDENT-VERIFICATION.md` | 288 lines | normative document: the problem; the trust-root contract; policy selection; why a symmetric signature cannot establish independence; the nine checks; the four outcome states and what each licenses; the real result; the controls; the complete refusal table; the boundary with A14–A17; non-claims; `NOT_RUN`; reproduction |
| `forensics/tools/independent_verify.py` | 1,110 lines | `load_inventory`, `policy_from_inventory`, `qualify`, `verify`, the 15 codes and the `roots`/`verify`/`qualify` command line; no signature primitive |
| `forensics/tools/tests/test_independent_verify.py` | 480 lines | 38 controls: one control per code, the envelope-keyid rule, HMAC refusal, candidate-tree root, inventory-in-candidate-evidence, same-domain root, self-issued basis, no-public-verifier `NOT_RUN`, the four real envelopes, the stub positive control, subject re-hashing, determinism, CLI exit codes with printed codes, document synchronisation, outcome-state distinctness |
| `evidence/a12/TRUST-ROOTS.json` | 47 lines / 1,739 bytes | the real inventory: one root, the A10 test-only HMAC-SHA256 key, `symmetric: true`, `trustDomain: same-party`, provenance inside the candidate, and an explicit statement that `externalRoots` is empty |
| `evidence/a12/VERIFICATION.json` | 448 lines / 14,993 bytes | the four real envelopes, their artefacts, outcomes, every code that fired, the check-by-check record and the explicit `independentlyVerified: 0` |
| `evidence/a12/CONTROLS.json` | 171 lines / 6,144 bytes | 15 controls over the 15 codes, plus the `control-only` stub-verifier positive control |
| `evidence/a12/build_evidence.py` | 591 lines | deterministic producer of the inventory, the verification and the controls; reads every digest from bytes; asserts every outcome and code |
| `evidence/a12/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A12 row only; no other row was touched. The
`spec_guard` pinned token set for that file did not drift (§6).

## 3. The rule

> An envelope is independently verified only when the verifier's root of trust is
> outside the candidate under test, outside the party that produced the envelope,
> and selected by a recorded policy rather than by the envelope. A symmetric
> signature can never establish independence: the verifier holds the same secret
> as the signer, so it could have produced the signature.

The sentinel is the root, not the signature. A10 already proves that a signature
verifies over the received PAE under the test-only key. A12 asks who selected that
key and whether the verifier could have made the signature itself. The honest
answer for the four real envelopes is **0 independently verified**.

## 4. The trust-root contract and the policy

A root records `keyid`, `algorithm`, `publicMaterial` (or an explicit
`symmetric: true`), `provenance` (`path`, `sha256`), `trustDomain`,
`independenceBasis` and `recordedAt`. The inventory is a separate tracked record
and must not lie inside the candidate evidence being verified.

The policy names the keyid. The envelope's keyid is an unauthenticated hint,
recorded for comparison only. If the policy names no keyid, the verifier does not
fall back to the envelope: `IV_REFUSED_KEY_FROM_ENVELOPE`. If the policy names a
keyid absent from the inventory, the result is
`IV_REFUSED_TRUST_ROOT_UNRECORDED`, even when the envelope carries a recorded keyid.

The caller supplies
`public_verify(keyid, pae_bytes, signature_bytes, public_material) -> bool`. The
module implements no signature primitive. With no verifier and an otherwise
acceptable root the outcome is `NOT_RUN` with
`IV_REFUSED_NO_PUBLIC_VERIFIER`, never a pass. When a root-level refusal has
already decided that the envelope is not independent, the outcome is
`SELF_ISSUED` (or `UNVERIFIED`) even without a verifier, because the independence
question is decided by the root, not by an unchecked signature.

## 5. The real verification

| envelope | artefact | outcome | codes |
|---|---|---|---|
| `evidence/a10/ENVELOPES/a1-sarif.json` | `evidence/a1/SARIF.json` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |
| `evidence/a10/ENVELOPES/a5-admission.json` | `evidence/a5/ADMISSION.json` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |
| `evidence/a10/ENVELOPES/a7-delta.json` | `evidence/a7/DELTA.json` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |
| `evidence/a10/ENVELOPES/a8-shard-000.json` | `evidence/a8/SHARD-000.sarif` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |

**Aggregate: 0 independently verified, 4 self-issued, 0 unverified, 0 not run.**
The producer also records `signatureChecked: true` for each, using the A10
test-only HMAC verifier as a caller-supplied check, so the record shows that the
received signature is the one A10 made *and* that independence is refused at the
root. The signature check does not upgrade the outcome.

The only recorded root is `test-only:hmac-sha256:8e10a5a15d233d54`, with
`algorithm: hmac-sha256`, `symmetric: true`, `publicMaterial: null`,
`trustDomain: same-party`, `selfIssued: true`, and provenance
`evidence/a10/ENVELOPES.json` (`3eb66119…`) inside the candidate. The inventory
states `externalRoots: []` and explains that the absence is the measured state,
not an omission.

## 6. The controls

`evidence/a12/CONTROLS.json` records one control per refusal code: 15 controls
over 15 codes. Each is built from a stub-signed A1 statement and a control root,
and each asserts its named code.

| control | code | outcome |
|---|---|---|
| `envelope-invalid` | `IV_REFUSED_ENVELOPE` | `UNVERIFIED` |
| `key-from-envelope` | `IV_REFUSED_KEY_FROM_ENVELOPE` | `UNVERIFIED` |
| `symmetric-root` | `IV_REFUSED_SYMMETRIC` | `SELF_ISSUED` |
| `candidate-trust-root` | `IV_REFUSED_CANDIDATE_TRUST_ROOT` | `SELF_ISSUED` |
| `trust-root-unrecorded` | `IV_REFUSED_TRUST_ROOT_UNRECORDED` | `UNVERIFIED` |
| `trust-root-digest-mismatch` | `IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH` | `UNVERIFIED` |
| `same-domain` | `IV_REFUSED_SAME_DOMAIN` | `SELF_ISSUED` |
| `self-issued-basis` | `IV_REFUSED_SELF_ISSUED` | `SELF_ISSUED` |
| `signature-invalid` | `IV_REFUSED_SIGNATURE` | `UNVERIFIED` |
| `payload-not-subject` | `IV_REFUSED_PAYLOAD_NOT_SUBJECT` | `UNVERIFIED` |
| `subject-absent` | `IV_REFUSED_SUBJECT_ABSENT` | `UNVERIFIED` |
| `subject-mismatch` | `IV_REFUSED_SUBJECT_MISMATCH` | `UNVERIFIED` |
| `no-public-verifier` | `IV_REFUSED_NO_PUBLIC_VERIFIER` | `NOT_RUN` |
| `trust-root-stale` | `IV_REFUSED_TRUST_ROOT_STALE` | `UNVERIFIED` |
| `multiple-roots` | `IV_REFUSED_MULTIPLE_ROOTS` | `UNVERIFIED` |
| `stub-verifier-public-key` (control-only) | — | `INDEPENDENTLY_VERIFIED` |

**The positive control is `control-only`.** A caller-supplied stub verifier
accepts a distinct public-key root and the outcome becomes
`INDEPENDENTLY_VERIFIED`. It establishes that the decision procedure is reachable
and that the outcome state is not vacuous. It does **not** establish a real
independent party: the verifier is a test stub, no signature primitive is
implemented, and no real envelope is independently verified. It is excluded from
the real aggregate of 0.

| quantity | measured |
|---|---:|
| refusal codes | 15 |
| controls | 15 (one per code) |
| positive controls | 1 (`control-only`) |
| real envelopes | 4 |
| real independently verified | **0** |
| real self-issued | **4** |
| new `unittest` controls | 38 |
| whole tools suite | 1,149 (1,111 before this item) |

## 7. Defects found

**No existing tracked record was defective and no existing record was edited.**
The A10 envelopes, the A9 statements and the A1/A5/A7/A8 artefacts were re-read as
bytes and re-hashed; every subject digest matched. `docs_consistency.py` and
`spec_guard.py check` were clean before and after; the pinned token set for
`docs/ETP-TODO.md` did not drift.

Three defects were found in this item's own new files and are preserved with the
old and the new form. None was a silent pass: each failed loudly before a record
was written or a gate was reported.

| file | old form | new form | found by |
|---|---|---|---|
| `forensics/tools/independent_verify.py` | a procedural root refusal (`IV_REFUSED_KEY_FROM_ENVELOPE`) with no public verifier fell through to `NOT_RUN`, because the no-verifier branch preceded the other-failure branch | `other_failures` is decided before the no-verifier branch, so a procedural refusal is `UNVERIFIED` and only an otherwise acceptable root with no verifier is `NOT_RUN` | `test_the_envelope_keyid_cannot_select_a_root` (failed with `NOT_RUN != UNVERIFIED`) |
| `evidence/a12/build_evidence.py` | `_run(..., verifier=None)` could not be distinguished from "use the fixture verifier", so the `no-public-verifier` control exercised the stub and did not produce `IV_REFUSED_NO_PUBLIC_VERIFIER` | a module-level sentinel (`_NOT_GIVEN`) distinguishes "not supplied" from an explicit `None` | the producer's own assertion, before the first recorded run |
| `evidence/a12/build_evidence.py` | the `candidate-trust-root` control pointed the provenance at `evidence/a10/ENVELOPES.json` but left the candidate root at the temporary directory, so the provenance was outside the candidate and the control reached `INDEPENDENTLY_VERIFIED` | the control sets `policy.candidateRoot` to the repository root as well as the candidate provenance | the producer's own assertion (`expected IV_REFUSED_CANDIDATE_TRUST_ROOT, got []`) |

**Gate history preserved.** The first whole-suite run in the court used
`sh -lc`, whose login-shell profile reset `PATH`, and read
`Ran 1147 tests in 210.084s`, `FAILED (failures=11, errors=1)`: 11 failures and 1
error in `test_binary_assurance` and `test_instrument_qualify`, caused by
`rustc`/`cargo`/`binsec` not being on that reset `PATH` and by a live TCB `cargo`
digest resolving to the toolchain binary rather than the rustup shim. The tests
were not relaxed; the shell invocation and `PATH` were corrected to the image's
pinned tool paths, both modules passed (25/25 and 16/16), and the whole suite then
read `Ran 1147 tests in 212.121s`, `OK`, and after the final control was added
`Ran 1149 tests in 212.495s`, `OK`. The final gate output is in §8.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time, with
the tool `PATH` recorded in §1.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 23 18 0 4 22` (available 22 GiB); `Swap: 45 27 18` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1149 tests in 212.495s`; `OK` (**1,111 before + 38 new = 1,149, 0 failures, 0 errors, 0 skipped**; no test removed, none newly ignored) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| JSON well-formedness | `python3 -m json.tool` on `TRUST-ROOTS.json`, `VERIFICATION.json`, `CONTROLS.json` | `ok` for all three, exit 0 each |
| producer, two runs | `python3 evidence/a12/build_evidence.py --out /tmp/a12a --source-commit 1d571da35` and the same to `/tmp/a12b` | `a12: envelopes=4 independentlyVerified=0 selfIssued=4 unverified=0 notRun=0 codes=15 controls=15 commit=1d571da35` twice |
| producer byte-identity | `cmp` of `/tmp/a12a/<name>`, `/tmp/a12b/<name>` and `evidence/a12/<name>` | `identical` for `TRUST-ROOTS.json`, `VERIFICATION.json` and `CONTROLS.json` |
| the real verification | `python3 forensics/tools/independent_verify.py verify` on the four envelope/artefact pairs | each `code=IV_REFUSED_SYMMETRIC outcome=SELF_ISSUED independentlyVerified=false … codes=IV_REFUSED_SYMMETRIC,IV_REFUSED_CANDIDATE_TRUST_ROOT,IV_REFUSED_SELF_ISSUED`, exit 1; aggregate **0 independently verified** |
| inventory and qualification | `python3 forensics/tools/independent_verify.py roots` and `qualify` | `roots: code=IV_OK roots=1 externalRoots=0 symmetricRoots=1 … outcome=NOT_RUN`; `qualify: code=IV_OK roots=1 externalRoots=0 symmetricRoots=1 outcome=NOT_RUN` |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/INDEPENDENT-VERIFICATION.md`, `?? evidence/a12/`, `?? forensics/tools/independent_verify.py`, `?? forensics/tools/tests/test_independent_verify.py` |

**Reproducibility.** The producer reads the real envelopes, A9 statements and
artefacts from their bytes; every digest is computed, nothing is typed. The source
identity is supplied (`--source-commit`); without it the recorded `BASE_COMMIT` is
reused, never a live `HEAD`. Two runs are byte-identical and the committed files
match a fresh build, enforced by
`test_the_producer_is_deterministic_and_matches_the_committed_bytes` and
`test_the_source_identity_is_supplied_not_read_live`.

## 9. Obligations retained

* **No external trust root.** The inventory records zero external roots. No key
  ceremony, external operator or published key exists; the four envelopes cannot
  be independently verified until one does.
* **No production signature primitive.** The module implements none; the caller
  supplies a verifier. The positive control uses a stub, and the real evidence
  uses the A10 test-only HMAC verifier only to confirm the received signature.
* **The root record does not prove the key's owner.** It records a trust domain
  and an independence basis; it does not establish that the party named owns the
  key. That is review, A16 and A18 work.
* **Freshness is evaluated against the recorded `asOf`.** It is not a live-clock
  check, so the evidence is deterministic.
* **No omission resistance.** A12 verifies an envelope that exists; it cannot
  detect an envelope or record that was never published. A17 owns that.
* **No independent review.** The author of the tool, document and controls is not
  an independent adjudicator of the code-to-conclusion mapping.
* **The stub-verifier positive control is not independence.** It establishes the
  decision procedure only and is excluded from the real aggregate.

## 10. `NOT_RUN`

* **A real external trust root, key ceremony or external operator.** None exists.
* **A production signature primitive.** None is implemented or used.
* **A14 role-bound authorisation, A15 thresholds over trust domains, A16 Sigstore
  bundles, A17 transparency.** Not implemented here.
* **A live-clock freshness check.** The policy's recorded `asOf` is used.
* **BOUNDARY and SEAL.** No caller/dependency-closure audit, no independent
  reviewer, no full forensic regeneration or downstream replay.
* **The Rust suite.** `src/` was not modified, so no rebuild or `cargo test` was
  run.

## 11. Boundary with A10, A14–A17 and the rest

A10 owns the DSSE envelope, the PAE and verification over received bytes; it
explicitly hands authenticity, trust-root and independent-verification to A12.
A12 owns only the trust decision: which key, selected by which policy, with which
provenance, in which trust domain. A14 owns whether a correctly verified key is
authorised for a role; A15 owns thresholds over distinct keys and domains; A16
owns Sigstore bundles and identity binding; A17 owns transparency and omission
resistance. A12's green result would be necessary for those, never sufficient.

The four real envelopes remain A10 framing results under a test-only key. A12
adds the measured fact that none of them is independently verified, and records
that fact rather than working around it.
