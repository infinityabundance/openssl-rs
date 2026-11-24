# A16 receipt — Sigstore bundles, offline verification

## 1. Identity of this batch

| field | value |
|---|---|
| item | A16 (Sigstore bundle profile with certificates, transparency entries, inclusion proofs and timestamps; offline verification with stated trust-root and freshness assumptions) |
| branch | `staging` |
| HEAD at the start | `67187c39ee5b5e6d2f66136829295c44096ddd08` (`a15: a threshold counts domains, not labels`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 22 19 0 4 23` (total 45, used 22, free 19, available **23** GiB); `Swap: 45 33 12` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, 6 GiB cap, Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The machine had 23 GiB available, below the 24 GiB floor §6.1 sets for a
build. No build was needed or run: every gate is Python-only. The already-running
6 GiB court was reused, as A7–A15 did, and every gate ran inside it with
`PYTHONDONTWRITEBYTECODE=1` so the bind-mounted tree gained no `__pycache__`
entries. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/sigstore_bundle.py` | 1,942 | the offline validator: strict parse, profile shape, certificate DER reader, 23 codes, structural no-network rule, inventory, CLI |
| `forensics/tools/tests/test_sigstore_bundle.py` | 519 | 39 controls: all codes, boundary cases, digest binding, inclusion variants, no-verifier outcomes, structural no-network, determinism, CLI, document synchronisation |
| `docs/SIGSTORE-BUNDLES.md` | 384 | normative: problem, profile, fields, offline order, what each check establishes and cannot, trust-root/freshness assumptions, real inventory, controls, refusal table, no-network rule, non-claims, `NOT_RUN` |
| `evidence/a16/INVENTORY.json` | 57 | the measured population: 0 bundles, 0 transparency logs, 0 certificates, 4 A10 self-issued DSSE envelopes |
| `evidence/a16/PROFILE.json` | 188 | the v0.3 profile, field by field, with trust-root and freshness assumptions |
| `evidence/a16/CONTROLS.json` | 4,348 | 27 `control-only` fixtures covering all 23 codes, four boundary cases and one positive control |
| `evidence/a16/build_evidence.py` | 860 | deterministic producer: synthetic DER certificates, the fixtures, the inventory and the profile |
| `docs/ETP-TODO.md` | 339 | the A16 row replaced only; no other row touched |
| `evidence/a16/RECEIPT.md` | this file | the receipt |

## 3. The rule

> A bundle carries the evidence, not the roots. The log public key, the CA root
> and the timestamp-authority root are supplied by policy and are not in the
> bundle. An offline validator must not claim verification when the material it
> would need is absent: a missing root or verifier is `NOT_RUN`, and `NOT_RUN`
> is never a pass.

`BUNDLE_VERIFIED_OFFLINE` means: every check ran and every caller-supplied
verifier accepted. It does not mean the log, the CA or the TSA is trustworthy,
that the payload is true, or that a bundle exists here. It does not.

## 4. The real inventory

`evidence/a16/INVENTORY.json` measured the tree, not the intention:

| quantity | measured |
|---|---:|
| Sigstore bundles | **0** |
| transparency logs (distinct log keys inside bundles) | **0** |
| certificates (inside bundles) | **0** |
| A10 self-issued DSSE envelopes (not bundles) | 4 |

The scan population is every `evidence/**/*.json` file (407 files). A file is a
bundle only when its top level carries a Sigstore bundle media type. Two files
mention the media type and are not bundles: `evidence/a16/PROFILE.json` (the
profile constant) and `evidence/a16/CONTROLS.json` (synthetic fixtures). They are
listed as candidate files with `topLevelMediaType: null`, not silently dropped.

There is no Sigstore bundle to verify, no log public key, no CA root and no
timestamp-authority root. The four A10 envelopes are HMAC-SHA256 envelopes over
a fixed public test seed (`test-only:hmac-sha256:8e10a5a15d233d54`); they carry
no certificate, no transparency entry, no inclusion proof and no timestamp, and
are not Sigstore bundles. Every real `validate` invocation is `NOT_RUN`.

## 5. Profile, and what cannot be checked offline

The profile is v0.3 only. v0.1 and v0.2 use a different shape and versioned media
type, so they are refused as unsupported rather than read with v0.3 field names.

Fields: `mediaType`; `verificationMaterial` with `x509CertificateChain` (a
public-key-only bundle is recognised and refused, because the profile requires an
issuer, a SAN and a validity window); canonical base64 DER certificates; the
certificate validity window `[notBefore, notAfter]` inclusive; the claimed issuer;
the SAN; `dsseEnvelope.payloadType`, `.payload`, `.signatures[]`;
`tlogEntries[].logIndex`, `.logId.keyId`, `.kindVersion` (`dsse` / `0.0.1`),
`.integratedTime`, `.inclusionPromise` or `.inclusionProof`;
`.timestampVerificationData.rfc3161Timestamps[]`.

The validator extracts the certificate's **claimed** issuer, SAN and window with
a minimal DER reader. It implements no signature primitive, builds no path and
verifies no inclusion mathematics. The four verifiers are caller-supplied:
`cert_verify`, `signature_verify`, `log_verify`, `timestamp_verify`.

Assumptions that cannot be checked offline, stated explicitly:

1. The log public key (`policy.logKey`) and `log_verify`. Absent here; inclusion
   is `NOT_RUN` (`SB_REFUSED_LOG_KEY_ABSENT`) and the outcome cannot be verified.
   The validator cannot establish that the log is append-only, honest or
   globally consistent.
2. The CA root (`policy.caRoots`) and `cert_verify`. Absent here; the chain is
   `NOT_RUN` (`SB_REFUSED_CERT_ROOT_ABSENT`). A parsed certificate is not a
   verified chain, and revocation (OCSP/CRL) is not checked.
3. The timestamp-authority root (`policy.timestampRoots`) and
   `timestamp_verify`. Absent here; the timestamp is `NOT_RUN`
   (`SB_REFUSED_TIMESTAMP_ROOT_ABSENT`). Presence is not verification.
4. The expected issuer and identity (`policy.expectedIssuer`,
   `policy.expectedIdentity`). Absent means `SB_REFUSED_POLICY_ABSENT` and
   `NOT_RUN`, not "any issuer and any SAN".
5. Freshness is judged at the tlog entry's `integratedTime`, not at a live
   clock; the window is inclusive at both ends. The profile cannot establish that
   a revocation did not happen after `integratedTime`.

## 6. The controls

`evidence/a16/CONTROLS.json` holds 27 synthetic fixtures covering all 23 refusal
codes, four boundary cases and one positive control. Every fixture is labelled
`control-only`. The synthetic certificates are structurally valid DER with a
placeholder signature: they establish the parse and the decision procedure, not a
real signing event and not an automated build provenance.

| control | decisive case |
|---|---|
| `media-type` | an ordinary JSON object is not a bundle |
| `version-v0.2` | the v0.2 shape is refused as unsupported, not guessed |
| `bundle-invalid-no-envelope` | a missing DSSE envelope is invalid |
| `duplicate-key` | `harden.loads` refuses a second `mediaType` |
| `material-absent` | no verification material means no signer |
| `cert-chain-empty` | an empty certificate list is not a chain |
| `cert-root-absent` | a parsed certificate is `NOT_RUN`, not verified |
| `certificate-expired-at-integrated-time` | one second after `notAfter` is out |
| `certificate-not-yet-valid-at-integrated-time` | one second before `notBefore` is out |
| `issuer-mismatch` | the policy issuer is binding |
| `identity-mismatch` | the policy SAN is binding |
| `payload-digest` | the signature is over one artefact, not another |
| `tlog-absent` | no entry means no log claim |
| `tlog-kind` | `hashedrekord` is not this envelope's DSSE entry |
| `integrated-time-index-disagreement` | the proof index must agree with the entry |
| `inclusion-proof-absent` | an entry with no promise and no proof is unproven |
| `inclusion-proof-rejected` | a present proof the verifier rejects is not inclusion |
| `log-key-absent` | presence of a proof is not verification of it |
| `timestamp-absent` | the profile requires a timestamp |
| `timestamp-root-absent` | a timestamp without a TSA root is `NOT_RUN` |
| `timestamp-rejected` | a rejected timestamp is not freshness |
| `signature-rejected` | a rejected DSSE signature is not authentication |
| `signature-verifier-absent` | no verifier means `NOT_RUN`, not accepted |
| `policy-absent` | no expected issuer/identity means `NOT_RUN` |
| `input-absent` | absence is `NOT_RUN`, never a pass |
| `network-import`, `sigstore-client-invocation` | the structural rule fires |
| `positive-structurally-complete` | the full procedure reaches `BUNDLE_VERIFIED_OFFLINE` under stubs only |
| `at-not-before`, `at-not-after` | the window is inclusive at both edges |
| `one-second-before-not-before`, `one-second-after-not-after` | one second outside is invalid |

The positive control is excluded from the real inventory. It establishes the
decision procedure, not a real bundle, log, CA, TSA or build.

## 7. Defects found

**No existing record was rejected.** The full tools suite was green at the base
(1,321 tests) and is green after the change (1,360 tests); `docs_consistency.py`
and `spec_guard.py check` are clean before and after; all three new JSON records
pass `python3 -m json.tool`. No contradiction was found across A10's envelopes,
A12's roots and this item: A10 records four self-issued DSSE envelopes, A12
records one same-party root and 0 external roots, and A16 records 0 bundles, 0
log keys and 0 certificates. The absence is recorded, not repaired into a
bundle.

Four defects were found in this item's own new code, each before a green report:

| file | old form | new form | found by |
|---|---|---|---|
| `evidence/a16/build_evidence.py` | `_run()` encoded `None` when neither `bundle` nor `bundle_bytes` was given, so every verifier-only control validated the bytes `null` and failed with `SB_REFUSED_BUNDLE_INVALID` | `_run` and `_control` default to `base_document()` before encoding; the verifier-only controls validate the real base bundle and record it | the producer's own assertion: `control cert-root-absent failed: expected SB_REFUSED_CERT_ROOT_ABSENT, observed ['SB_REFUSED_BUNDLE_INVALID']` |
| `forensics/tools/sigstore_bundle.py` | a refusal raised inside `_strict_bundle` (including the duplicate-key path) produced a report with an empty `checks` list, so the failing check was not named | `validate_bundle` appends the failing `strict-json` check when no check already records that code | `test_every_control_observed_its_expected_code`: `'fail' not found in dict_values([]) : duplicate-key` |
| `forensics/tools/tests/test_sigstore_bundle.py` | the per-control assertion assumed every fixture has an `outcome`; source-inspection controls record findings instead | structural controls are skipped for the outcome assertion after their code is checked | `KeyError: 'outcome'` in the same test |
| `docs/SIGSTORE-BUNDLES.md` | the non-claims used `does **not mean**` and the section heading was `## 12. \`NOT_RUN\``; the synchronisation test looks for the plain phrase and the exact heading | the phrases are plain and the heading is exactly `## \`NOT_RUN\`` | `test_the_document_states_the_assumptions_and_non_claims` and `test_the_document_has_a_not_run_section` |

The first defect was in the producer, not the validator: it proved the
verifier-only controls were not exercising the bundle they claimed to exercise.
The second was in the report assembly, not the decision: the refusal fired
correctly, but the report did not name the check that failed. Both are preserved
here rather than rewritten.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time,
with `PYTHONDONTWRITEBYTECODE=1`.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 22 19 0 4 23` (available 23 GiB); `Swap: 45 33 12` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1360 tests in 222.472s`; `OK`; `closure discipline self-test: 7 control groups passed`. **1,321 pre-existing tests are present** (1,321 + 39 = 1,360), **none ignored** |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `INVENTORY.json`, `PROFILE.json`, `CONTROLS.json` | `json.tool ok` for all three, exit 0 each |
| producer, two runs | `python3 evidence/a16/build_evidence.py --out /tmp/a16a` and the same to `/tmp/a16b` | `a16: bundles=0 logs=0 certificates=0 controls=27 codes=23 boundaries=4 positive=BUNDLE_VERIFIED_OFFLINE commit=67187c39e` twice |
| producer byte-identity | `cmp` of `/tmp/a16a/<name>`, `/tmp/a16b/<name>` and `evidence/a16/<name>` | `identical: <name> (run1=run2=committed)` for all three |
| the real inventory | `python3 forensics/tools/sigstore_bundle.py inventory` | `inventory: code=SB_OK outcome=NOT_RUN bundles=0 transparencyLogs=0 certificates=0 population=407 files`, exit 0 |
| every bundle in the tree | the `bundleFiles` list of `INVENTORY.json` | `bundleFiles=0`; **0 bundles, 0 `validate` invocations, inventory outcome `NOT_RUN`** |
| an absent record | `python3 forensics/tools/sigstore_bundle.py validate control-only/absent.bundle.json control-only/absent.artefact` | `validate: code=SB_REFUSED_INPUT_ABSENT outcome=NOT_RUN mediaType=None checks=1 notRun=SB_REFUSED_INPUT_ABSENT`, exit 1 |
| focused controls | `python3 -m unittest forensics.tools.tests.test_sigstore_bundle` | `Ran 39 tests in 2.820s`; `OK` |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/SIGSTORE-BUNDLES.md`, `?? evidence/a16/`, `?? forensics/tools/sigstore_bundle.py`, `?? forensics/tools/tests/test_sigstore_bundle.py` |

**Reproducibility.** The producer reads the tree's bundle population and the
bytes of its own tool and the two delegated tools (`harden.py`, `dsse.py`);
every digest is computed from bytes. Two runs are byte-identical and the
committed files match a fresh build, enforced by
`test_two_runs_are_byte_identical_and_match_committed` and
`test_the_producer_is_deterministic_in_process`. The source identity is supplied
(`--source-commit`); without it the recorded `BASE_COMMIT` is reused, never a
live `HEAD`.

## 9. Obligations retained

* **No bundle, log key, CA root or TSA root exists.** A16 validates the decision
  procedure and records the zero inventory; it does not create a trust domain.
  A real bundle, a real log public key and a real CA/TSA ceremony are external
  work (A17 and beyond), not a defect to be patched in this item.
* **The bundle profile is v0.3 only.** v0.1 and v0.2 are refused as unsupported.
  Validating their shapes is a separate change with its own controls.
* **Public-key-only bundles are refused, not validated.** The profile requires an
  X.509 issuer, SAN and window; a key-only bundle cannot satisfy it. Supporting
  key-based bundles is a separate profile.
* **The certificate's issuer, SAN and window are self-asserted until the path
  verifies.** The profile records this; it does not make the claimed fields
  authenticated.
* **No inclusion mathematics is implemented.** `log_verify` is the caller's; the
  profile checks presence and structure only.
* **No revocation check.** The window at `integratedTime` cannot establish that
  the certificate was not revoked later.
* **`docs/RELEASE_GATES.md` §10 is not updated.** The bundle row is not wired
  into the release gate; the constitution's gate-item table is unchanged. That
  integration is a separate change.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## 10. `NOT_RUN`

* Any real Sigstore bundle: **0** exist in this tree.
* Any real transparency-log public key, inclusion-proof verification,
  append-only check or consistency proof: no log key and no `log_verify` exists.
* Any real CA root, certificate-path validation or revocation (OCSP/CRL) check:
  no CA root and no `cert_verify` exists.
* Any real timestamp-authority root or RFC 3161 verification: no TSA root and no
  `timestamp_verify` exists.
* Any real DSSE signature over a certificate's key: no key and no
  `signature_verify` exists. The A10 envelopes are test-only HMAC and A12 records
  them `SELF_ISSUED`.
* A live-clock freshness check: freshness is judged at `integratedTime`; no clock
  is read.
* An online Rekor/Rekor v2 lookup, a Sigstore client invocation and any network
  call: forbidden structurally and not attempted.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite (`src/` was
  not modified, so no rebuild and no `cargo test` is claimed).

## 11. Correction — the population was bound to a live glob (found by A17)

**Found by A17.** A17's whole-suite run reported `Ran 1403 tests` /
`FAILED (failures=1)`:

```
FAIL: test_two_runs_are_byte_identical_and_match_committed
(test_sigstore_bundle.DeterminismAndRecords)
AssertionError: ... "populationFiles": 413 ... != ... "populationFiles": 407 ...
: committed differs: INVENTORY.json
```

A17 recorded it as an A16 record repair and did not edit it. This section is that
repair. Nothing above is rewritten.

### What was wrong

`INVENTORY.json` recorded `populationFiles: 407`, read from the **live glob**
`evidence/**/*.json`. A17's six new records made the live count 413, so the
committed record stopped reproducing at HEAD. This is the same defect class as
the two already repaired in A11 (a live glob presented as a fixed population) and
the A7 defect (a live `HEAD` presented as an identity): a record bound to a
moving measurement.

The old 407 was itself the wrong population. It was the 404 evidence JSON files
at the declared candidate `67187c39e` plus this item's own three records
(`INVENTORY.json`, `PROFILE.json`, `CONTROLS.json`), which were added after that
candidate. A record cannot contain its own sha256, so `INVENTORY.json` can never
be a member of its own population.

### The new contract

* The population is an **explicit frozen member list**: the 404 tracked
  `evidence/**/*.json` files that existed at `67187c39e`, each recorded as
  `{path, sha256, bytes}` and re-hashed on every verification
  (`population.members`, `population.binding: "FROZEN"`,
  `population.frozenAtCandidate`). `populationFiles` is the length of that list
  (`404`), not a count of the glob.
* The certificate globs are frozen the same way
  (`certificatePopulation.members`, empty at the candidate);
  `certificateFiles` is that list's length (`0`).
* The A10 envelope count is now read from the frozen members
  (`a10Envelopes: 4`) instead of from a live directory listing.
* A file matching the glob that is not a member is reported as
  **`NEW_SINCE_RECORD`** with its path, sha256 and size, counted separately. The
  recorded count is unchanged. At this commit that report is the three A16
  records and A17's six records (nine files) — printed by
  `sigstore_bundle.py inventory` and by the producer on stderr, never stored in
  the record, so the record still reproduces at later commits.
* A **new bundle would appear as `NEW_SINCE_RECORD`** and would require an
  explicit re-freeze and a fresh inventory before it could be counted; it is not
  silently included. The producer re-freezes only with
  `--freeze-population CANDIDATE`, which enumerates that candidate's tree and
  refuses if any member's bytes changed since (`PH_REFUSED_POPULATION_DRIFT`).
* A changed or removed member is refused with `PH_REFUSED_POPULATION_DRIFT`
  (`harden`'s stable population-drift code). No `SB_REFUSED_*` code was added,
  removed or relaxed.
* The machinery is `harden.freeze_population`, `harden.population_growth`,
  `harden.Refusal`, `harden.POPULATION_FROZEN`, `harden.RESULT_NEW_SINCE_RECORD`
  and `harden.PH_REFUSED_POPULATION_DRIFT`, imported. **`harden.py` was not
  modified.**
* The inventory schema is bumped to `openssl-rs/a16/bundle-inventory/2`; the
  record shape changed. `PROFILE.json` and `CONTROLS.json` change only in
  `sourceIdentity.tool.sha256` (one line each): the 27 control-only fixtures, the
  23 codes and the four boundary cases are unchanged.

### Old and new identity

| quantity | old | new |
|---|---|---|
| `INVENTORY.json` sha256 | `b6c06350098bda9227f58defc873b4676113cd54bceb89f4cb82497d18021bf1` | `a7e200603059828c113ad0704cd3a4b9a6e89feae5cbbd5b8b7e5dbbf03916c2` |
| population representation | live glob `evidence/**/*.json` | explicit 404-member `{path, sha256, bytes}` list |
| `populationFiles` | 407 (live) | **404** (frozen at `67187c39e`) |
| `certificateFiles` | 0 (live) | 0 (frozen empty member list) |
| bundles / logs / certificates | 0 / 0 / 0 | 0 / 0 / 0 |
| growth | absorbed into the count | 9 `NEW_SINCE_RECORD`, counted separately |

### Gates actually run (all in the reused 6 GiB `openssl-rs-court` container)

| gate | observed |
|---|---|
| `free -g` (host, before the work) | `Mem: 45 21 21 0 3 24` (available **24** GiB); `Swap: 45 37 8` |
| focused | `python3 -m unittest forensics.tools.tests.test_sigstore_bundle` → `Ran 51 tests`, `OK` (was 39) |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` → `Ran 1415 tests in 233.925s`, `OK`, `closure discipline self-test: 7 control groups passed` (parent 1403 with the one failure; 1403 + 12 new = 1415, none removed, newly skipped or newly ignored) |
| producer, two runs | `python3 evidence/a16/build_evidence.py --out /tmp/a16a` and `/tmp/a16b` → `a16: ... commit=67187c39e population=FROZEN files=404 growth=9` twice |
| byte identity | `cmp` → `identical: INVENTORY.json (run1=run2=committed)`, same for `PROFILE.json` and `CONTROLS.json` |
| growth control | nine `growth: result=NEW_SINCE_RECORD path=... sha256=... bytes=...` lines; `population: binding=FROZEN files=404 growth=9` — the count stayed 404 |
| JSON well-formedness | `python3 -m json.tool` → `json.tool ok` for all three records |
| documentation | `python3 forensics/tools/docs_consistency.py` → `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 |
| specification guard | `python3 forensics/tools/spec_guard.py check` → `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| `harden.py` | not modified (still `f05d7fe9be3933332a69f43ee3fab26f7c764a8f20ce556d295683fea7824023`) |

`docs/SIGSTORE-BUNDLES.md` §7 stated the population as a live glob ("every
`evidence/**/*.json` file"); it now states the frozen member list, names
`NEW_SINCE_RECORD`, and says a new bundle needs a re-freeze and a fresh
inventory. No other document was touched.

### Obligations retained

* **Any change to a member invalidates this record** until an explicit
  re-freeze: the population covers other items' evidence records, so editing one
  is refused as `PH_REFUSED_POPULATION_DRIFT` rather than silently absorbed.
  That refusal is the intended signal, not a defect.
* **`INVENTORY.json` appears in its own growth report** (it matches the glob and
  cannot be a member). That is expected; the report is a live projection and is
  not stored, so the record's bytes do not depend on it.
* **The growth list is the only place a post-candidate bundle is visible.**
  `bundles: 0` speaks for the frozen population, not for the current tree; the
  document says so. Re-freezing is a deliberate act with its own diff.
* No independent review of this correction; the author of the change is not an
  independent adjudicator of it.
