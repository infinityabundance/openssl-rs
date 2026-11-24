# Protocol and infrastructure audit (B0)

Status: normative for `forensics/tools/protocol_audit.py`. Delivered at base
`5015b6239` on `staging`, 2026-11-24. The records are
`evidence/b0/REGISTRY.json` and `evidence/b0/SERVICE-CONFIGURATION.json`; the
deterministic producer is `evidence/b0/build_evidence.py`; the controls are
`forensics/tools/tests/test_protocol_audit.py`; the receipt is
`evidence/b0/RECEIPT.md`. Addendum B is `docs/ETP-ADDENDUM-B.md`; the two files
are the forward-freeze members `b0-registry` and `b0-service-configuration`.

This document is cumulative with `AGENTS.md` and `docs/EARNED-TRUST.md`. It
separates two facts that are easy to confuse: what the addendum **pins**, and
what this tree actually **has**. A pinned version is not an installed component,
an installed component is not a running service, and a running service is not an
independent trust domain.

## 1. What the audit establishes, and what it does not

It establishes, from tracked records only:

* every admitted version, release date, upstream commit and the one recorded
  digest, each read from the clause that pins it;
* that each of those identities appears verbatim in that clause, so an invented
  version or digest is refused rather than stored;
* the four presence facts per component — pinned, installed, executable and the
  check that establishes them — as measured with `command -v` and a tracked-path
  search;
* what client support is present in this tree, module by module, with the
  refusal vocabulary each module actually defines;
* the recorded service-configuration finding and what it means for B1;
* the three recorded tensions and the consequence of each for this project;
* five admitted-but-unavailable primitives and six unmet trust assumptions.

It does **not** establish:

* that any pinned version is current or free of security advisories; §B.5
  requires that recheck at admission;
* that any component is installed, executable, reachable or operated;
* that a transparency service exists, that a witness exists, that a timestamp
  authority exists, or that any envelope is independently verified;
* that the `signing_config` observation is still true today; it is recorded from
  §B.3.3 and was not repeated here (no network access);
* that the addendum's list of instruments is complete, or that the registry's
  population is the whole universe of relevant components.

The registry is a construction record. It is not an operational record.

## 2. Sources

| source | what it supplies |
|---|---|
| `docs/ETP-ADDENDUM-B.md` §B.3.2 | the pinned release table, the three C2SP specifications, the one release-asset digest and the protocol facts |
| `docs/ETP-ADDENDUM-B.md` §B.3.3 | the three tensions, the ML-DSA-44 divergence and the `signing_config` finding |
| `docs/ETP-ADDENDUM-B.md` §B.5, §B.10, §B.11, §B.26 | the admission, service-discovery, witness and post-quantum clauses cited by features and refusals |
| `docs/ETP-ADDENDUM-B.md` §B.30 | the B0–B8 sequence this item is the first of |
| `evidence/a17/FREEZE-forward.json` | the two member ids and their exact paths |
| `evidence/a10/ENVELOPES.json`, `evidence/a9/STATEMENTS.json`, `evidence/a11/SCAN.json`, `evidence/a12/VERIFICATION.json`, `evidence/a16/INVENTORY.json`, `evidence/a18/INVENTORY.json` | the measured client-support counts |
| `forensics/tools/{dsse,intoto,harden,independent_verify,sigstore_bundle,key_lifecycle}.py` | the refusal vocabularies |

No source outside this repository is consulted and nothing is fetched.

## 3. The registry

Fifteen components. `pinned` is true for fourteen; the recorded finding is not a
pinned version. `installed` and `executable` are false for all fifteen.

| id | name | version | clause | digest |
|---|---|---|---|---|
| `rekor-tiles-v2.4.2` | sigstore/rekor-tiles | v2.4.2 | B.3.2 | `sha256:3af252cd…61e8a6` |
| `rekor-tiles-v2.4.1` | sigstore/rekor-tiles | v2.4.1 | B.3.2 | null |
| `rekor-tiles-v2.4.0` | sigstore/rekor-tiles | v2.4.0 | B.3.2 | null |
| `rekor-tiles-v2.3.0` | sigstore/rekor-tiles | v2.3.0 | B.3.2 | null |
| `rekor-tiles-v2.2.1` | sigstore/rekor-tiles | v2.2.1 | B.3.2 | null |
| `rekor-tiles-v2.2.0` | sigstore/rekor-tiles | v2.2.0 | B.3.2 | null |
| `rekor-tiles-v2.1.0` | sigstore/rekor-tiles | v2.1.0 | B.3.2 | null |
| `rekor-tiles-v2.0.1` | sigstore/rekor-tiles | v2.0.1 | B.3.2 | null |
| `rekor-tiles-v2.0.0` | sigstore/rekor-tiles | v2.0.0 | B.3.2 | null |
| `c2sp-tlog-tiles-v1.0.0` | c2sp.org/tlog-tiles | v1.0.0 | B.3.2 | null |
| `c2sp-tlog-checkpoint-v1.1.0` | c2sp.org/tlog-checkpoint | v1.1.0 | B.3.2 | null |
| `c2sp-tlog-cosignature-v1.1.0` | c2sp.org/tlog-cosignature | v1.1.0 | B.3.2 | null |
| `dsse-entry-type-change-v2.3.0` | DSSE entry type removed; hashedrekord | v2.3.0 | B.3.2 | null |
| `ml-dsa-44` | ML-DSA-44 checkpoint cosignature | ML-DSA-44 | B.3.3 | null |
| `sigstore-signing-config-v1-endpoint` | Sigstore signing_config | null | B.3.3 | null |

Each entry carries the release date, the upstream commit where one is recorded,
the role (`log`, `checkpoint`, `cosignature`, `client`, …), the artefact and a
`sources` clause. A `null` is never bare: a null version states why no version is
recorded, a null digest states why no digest is recorded, and a null commit
states why none exists.

### 3.1 Why only one digest

§B.3.2 records one release-asset digest: the `linux/amd64`
`rekor-server-aws` asset of `v2.4.2`, `sha256:3af252cd59adea029eea7ff325dee8adb65074e45d0c03aaa6c083eb2461e8a6`.
Every other digest is `null` with the reason that no tracked record carries one.
No digest is invented, and the checker proves it: a digest must appear verbatim
in the clause it cites.

Enforced by `PA_REFUSED_INVENTED_DIGEST`, `PA_REFUSED_DIGEST_UNSTATED` and
`test_an_invented_digest_is_refused`.

### 3.2 A finding about the one recorded digest

The only recorded digest is for the **AWS** server asset of `v2.4.2`. The backend
§B.3.2 records for this project's local and CI instances is the **POSIX** backend
introduced at `v2.1.0`. The recorded digest therefore does not admit the server
this project intends to run. B1 must record a digest for the exact server
artefact it installs; it may not reuse the AWS digest as though it named the
POSIX build. This is a gap, not a contradiction: the clause is explicit that the
digest is "the identity against which a downloaded server binary is checked
before execution", and no binary was downloaded.

Enforced by `PA_REFUSED_INVENTED_DIGEST` (a reused digest would still have to
appear in the clause) and `test_every_version_date_commit_and_digest_appears_in_its_clause`.

## 4. Pinned versus installed

These are four independent facts, not one progression:

| fact | meaning | this tree |
|---|---|---|
| `pinned` | a tracked record names the version and the clause that adopts it | 14 of 15 |
| `installed` | a check found the component on this host or in the court | 0 of 15 |
| `executable` | a check found the component runnable | 0 of 15 |
| `serviceReachable` | a service answers at an admitted endpoint | false |

The presence checks are recorded in `REGISTRY.json#/presenceCheck`: `command -v`
for `rekor-server`, `rekor-cli`, `rekor-tiles`, `cosign`, `sigstore` and
`tsget` returned absent; `command -v openssl` returned `/usr/bin/openssl`, which
is a TLS toolkit and not a transparency service. A tracked-path search found no
Rekor endpoint, log key or witness outside `docs/`.

`installed: true` or `executable: true` requires a `checkedBy` that resolves to a
recorded check whose result is a path. A positive claim whose check says
`absent` is refused. The audit's live re-check can only withdraw a positive
claim; it never adds one.

Enforced by `PA_REFUSED_UNCHECKED_PRESENCE` and
`test_an_installed_entry_with_an_absent_check_is_refused`.

## 5. The service-configuration finding

**SCF-1.** The Sigstore `signing_config` inspected on 2026-10-22 still advertised
a Rekor **v1** endpoint. Recorded in §B.3.3 item 2. The record's state here is
`RECORDED`, not `VERIFIED`: this item has no network access and did not repeat
the inspection.

What it means for B1:

* B1 may not assume that a v2 endpoint exists because the client is recent, and
  may not inherit an endpoint from a client default;
* B1 must deploy and pin its own POSIX-backed Rekor v2 instance (§B.21) and read
  the service metadata it actually uses (§B.10);
* a v1 fallback is not admitted; a weaker protocol profile is never adopted by
  silent fallback;
* the local instance is development infrastructure, not independent public
  accountability, and must not be presented as such.

Enforced by `PA_REFUSED_SERVICE_CLAIM` and `test_a_verified_finding_is_refused`.

## 6. The three tensions

| id | tension | consequence for this project |
|---|---|---|
| T1 | ML-DSA-44 is recommended by C2SP for new deployments and labelled experimental by the implementation (§B.3.3 item 1) | checkpoint post-quantum mechanisms stay on the research track (§B.26); no production claim cites the recommendation as available, and B1 uses the classical path |
| T2 | Service configuration is not implied by client version; the inspected `signing_config` advertised v1 (§B.3.3 item 2) | B1 deploys its own pinned v2 instance and B4 reads authenticated SigningConfig and TrustedRoot metadata; a client version is never evidence of a v2 service |
| T3 | Older documentation describes a dedicated DSSE entry type; since `v2.3.0` DSSE is published as `hashedrekord` (§B.3.3 item 3) | B1 derives the `hashedrekord` digest from the exact DSSE envelope as the admitted client does (§B.5); the envelope JSON, the payload alone and an unrelated manifest hash are not substitutes, and A10's PAE is framing, not the log-entry digest |

No tension is resolved by preference. `resolved` is false for all three.

Enforced by `PA_REFUSED_SERVICE_CLAIM` and `test_there_are_exactly_three_unresolved_tensions`.

## 7. Witness availability

Five primitives are admitted by the addendum and unavailable here. Each is
`available: false` and carries the check that establishes the absence. No witness
exists at any `n`: `witnessSet` records 0 operators, 0 keys, no quorum and
`independent: false`.

| id | primitive | record | what the record shows |
|---|---|---|---|
| `log-key` | the log key that verifies a checkpoint signature | `evidence/a16/INVENTORY.json` | 0 transparency logs, 0 certificates, no log key |
| `checkpoint-cosignature` | a cosignature over (origin, size, hash) | `evidence/a16/INVENTORY.json` | no checkpoint resource; `SB_REFUSED_LOG_KEY_ABSENT` |
| `witness-set` | independent witness keys with a quorum | `evidence/a12/TRUST-ROOTS.json` | 0 external roots; one symmetric same-party root |
| `rfc3161-tsa` | an admitted timestamp authority and root | `evidence/a16/INVENTORY.json` | no timestamp root; every timestamp check is `NOT_RUN` |
| `public-rekor-endpoint` | an authenticated public v2 endpoint | `docs/ETP-ADDENDUM-B.md` | no endpoint recorded; `signing_config` advertised v1 |

A witness class marked available without a recorded check, or a witness
population above zero, is refused.

Enforced by `PA_REFUSED_WITNESS_CLAIM` and `test_a_witness_marked_available_is_refused`.

## 8. Trust assumptions B1–B6 would require

Each is `UNMET`, with the record that shows it is unmet. A met assumption is
refused; nothing here asserts a trust path.

| id | item | assumption | why it is unmet |
|---|---|---|---|
| `TA-B1` | B1 | a pinned server binary matching a recorded digest runs with the POSIX backend and a log key this project controls | 0 installed, 0 executable; the only digest names the AWS build |
| `TA-B2` | B2 | an admitted RFC 3161 TSA with a trusted root and a verifier | 0 certificates and no timestamp root |
| `TA-B3` | B3 | an authenticated campaign signer that is not the producer | 0 of 4 envelopes independently verified; 4 self-issued |
| `TA-B4` | B4 | an admitted public-good v2 endpoint with authenticated SigningConfig and TrustedRoot | no endpoint; the inspected config advertised v1 |
| `TA-B5` | B5 | independent witnesses with a quorum and persistent state | 0 external roots, 0 operators, no persistence |
| `TA-B6` | B6 | an independent archive and a current-state revocation authority | 0 repositories and 0 revocation records |

Enforced by `PA_REFUSED_SERVICE_CLAIM` and `test_a_met_trust_assumption_is_refused`.

## 9. What this tree actually supports

Six modules are present. Each is an evidence-format tool, not a transparency
service. The registry's `clientSupport` entries carry the full refusal
vocabulary, and every named code is checked against the module source, so a
silent rename is a refusal rather than a stale list.

| item | module | supports | refusal vocabulary |
|---|---|---|---|
| A9 | `forensics/tools/intoto.py` | in-toto Statement v1, computed subject digests, record-bound predicates | 12 `IT_REFUSED_*` codes |
| A10 | `forensics/tools/dsse.py` | DSSE v1 envelope and the exact PAE over received bytes | 13 `DS_REFUSED_*` codes |
| A11 | `forensics/tools/harden.py` | one strict JSON reader for received evidence | 13 reader `PH_REFUSED_*` codes plus `PH_REFUSED_POPULATION_DRIFT` for a frozen population |
| A12 | `forensics/tools/independent_verify.py` | the independent-verification decision, four outcomes | 15 `IV_REFUSED_*` codes |
| A16 | `forensics/tools/sigstore_bundle.py` | an offline Sigstore bundle v0.3 profile validator | 23 `SB_REFUSED_*` codes |
| A18 | `forensics/tools/key_lifecycle.py` | rotation, delegation, expiry, revocation, anti-rollback, anti-freeze, stale releases | 21 `TK_REFUSED_*` codes plus `TK_NOT_RUN` |

The measured state is not a capability claim:

* A10 holds 4 envelopes, all signed by the test-only HMAC-SHA256 key;
* A9 holds 4 statements, one subject each;
* A11 examines 386 files, 211 strictly OK, 0 refused, 175 size-skipped; its
reader refuses with 13 `PH_REFUSED_*` codes, and the module additionally defines
`PH_REFUSED_POPULATION_DRIFT` for a frozen population, which is not a reader
refusal;
* A12 records **0 of 4 independently verified** and 4 self-issued;
* A16 records **0 bundles**, 0 transparency logs and 0 certificates;
* A18 records **0 repositories**, 1 symmetric test-only key, 0 revocation
  records, 0 metadata versions and 0 delegations.

The Sigstore bundle validator's declared limits matter here: the log key, CA
root, TSA root and expected identity are supplied by policy and are **not** in
the bundle or this tree, and every real `validate` invocation is `NOT_RUN`.

Enforced by `PA_REFUSED_UNSOURCED_FEATURE`, `PA_REFUSED_OBSERVATION_DRIFT` and
`test_every_client_support_module_and_code_is_present`.

## 10. The claims the record makes

`claimsMade` records fifteen claims, each with `established`. Seven service
claims (CLM-01…CLM-07) are false. CLM-08, that an envelope is independently
verified, is false. CLM-14, the `signing_config` finding, is **not established
here**: it is recorded by the addendum, not re-observed. Five implementation and
record claims are true and each names an existing evidence path.

A service claim can never be established from a pinned record. A claim marked
established must name evidence that exists, and a service claim marked
established is refused.

Enforced by `PA_REFUSED_UNEVIDENCED_CLAIM`, `PA_REFUSED_SERVICE_CLAIM` and
`test_no_service_claim_is_established`.

## 11. Refusal table

Every code is stable and is cited verbatim by the tool, the tests, this document
and the receipt.

| code | condition | prevents |
|---|---|---|
| `PA_REFUSED_UNSOURCED_VERSION` | a version, date or commit is absent with no reason, or does not appear in the cited clause | a version remembered or invented rather than read from the record |
| `PA_REFUSED_INVENTED_DIGEST` | a digest is malformed or does not appear in the cited clause | an unrecorded digest presented as an artefact's identity |
| `PA_REFUSED_UNCHECKED_PRESENCE` | installed or executable is true with no recorded check that resolves to a path | an installation asserted without a check |
| `PA_REFUSED_UNSOURCED_FEATURE` | a feature has no clause, or a named support has no implementation in its module | a capability claimed without a record that admits it |
| `PA_REFUSED_SERVICE_CLAIM` | a reachable service is claimed, a tension is resolved, a trust assumption is met, or the finding is verified | a pinned version read as a working service |
| `PA_REFUSED_MISSING_MEMBER` | a required component, support module, witness class, trust assumption or freeze member is absent | an omission read as completeness |
| `PA_REFUSED_CLAUSE_UNKNOWN` | a clause is outside the permitted set or has no text | an unread or mistyped clause accepted as a source |
| `PA_REFUSED_WITNESS_CLAIM` | a witness class is available, or a witness population is above zero, without a check | a witness asserted at some n when none is admitted |
| `PA_REFUSED_ENTRY_INCOMPLETE` | a required field is absent or mistyped, or a role, kind or state is unknown | a partial entry read as a complete record |
| `PA_REFUSED_DIGEST_UNSTATED` | a digest is null with no reason | an omitted digest indistinguishable from one never sought |
| `PA_REFUSED_UNEVIDENCED_CLAIM` | an established claim names no existing evidence | an established claim a reader cannot open |
| `PA_REFUSED_OBSERVATION_DRIFT` | a declared observed value no longer equals its record and pointer | a typed count read as a measurement |
| `PA_REFUSED_USAGE` | the command line is malformed | a malformed invocation read as a result |

Enforced by `test_every_refusal_code_is_in_the_table` and one control per code in
`forensics/tools/tests/test_protocol_audit.py`.

## 12. Non-claims

* **A registry is not a deployment.** No component is installed, started or
  operated by this item.
* **A pinned version is not an admitted service.** §B.5 admits a reviewed
  profile; the registry records the pins that profile will be built from.
* **This item runs no Rekor.** It also runs no witness, no timestamp authority
  and no Sigstore client, and it contacts no network.
* The `signing_config` finding is recorded from §B.3.3, not re-observed; it is
  `RECORDED`, not `VERIFIED`.
* 0 of 4 envelopes are independently verified; `SELF_ISSUED` is not a pass.
* A digest that is `null` is not a digest that was checked and found absent; it
  is a digest no tracked record contains.
* The presence observations are dated 2026-11-24. They are not a live guarantee,
  and the audit's live re-check can only withdraw a claim.
* The registry does not establish currency, absence of advisories, or that a
  pinned tag is safe to execute.
* No transparency guarantee, witness quorum or trusted time is established.

## `NOT_RUN`

* Any download, installation, execution or configuration of `rekor-tiles`, a
  Rekor client, `cosign` or a Sigstore CLI.
* Any network request, including the `signing_config` re-inspection.
* Any log-key generation, checkpoint signing or cosignature verification.
* Any RFC 3161 timestamp request or token verification.
* Any witness admission, quorum evaluation or split-view simulation.
* Any independent verification of a real envelope (A12 records 0 of 4).
* Any tile, entry bundle, inclusion proof or consistency proof.
* The security-advisory recheck §B.5 requires at admission.
* Independent review, BOUNDARY and SEAL evidence, and the Rust suite (`src/` was
  not modified).

## 13. Reproducing the evidence

```
python3 evidence/b0/build_evidence.py
python3 forensics/tools/protocol_audit.py registry
python3 forensics/tools/protocol_audit.py audit
python3 forensics/tools/protocol_audit.py claims
python3 -m unittest forensics.tools.tests.test_protocol_audit
```

The producer reads the addendum and writes both records; two runs are
byte-identical. `--check` validates the committed records without writing.
