# ETP-T2 receipt — security hazard register

**Item:** ETP-T2 of `docs/ETP-TODO.md`.
**Analysis candidate:** `staging` at
`6da02233f94152b865c9d02cdcfe5adeb34952e7`, worktree clean at the start.
**Graph commit:** `21bea318819a56f641b3aa2f25027216b97a1c4d` (the ETP-T1 seed).
**Evidence commit:** `UNKNOWN` at generation time; settled by
`git log -1 --format=%H -- evidence/etp-t2/HAZARDS.json`.
**Environment:** `openssl-rs-court-tools:1`, Python 3.11. `free -g` reported
26 GiB available; the computed cap was `min(8g, 26-16) = 8g`, and the run used
the more conservative 6g/6g. No Rust build, compiler, test or benchmark was run;
no `src/`, `docker/` or build input was touched.

## 1. Deliverables

| artefact | role |
|---|---|
| `docs/HAZARD-REGISTER.md` | the classification, fault trees, FMEA, STPA-Sec, attack graphs and non-claims |
| `evidence/etp-t2/HAZARDS.json` | machine-readable register (schema `openssl-rs/etp/hazards/1`), validated with `python3 -m json.tool` |
| `forensics/tools/hazard_register.py` | register validator and graph cross-check |
| `forensics/tools/tests/test_hazard_register.py` | 23 controls, including the class-3 refusals and graph drift |
| `forensics/tools/traceability.py` | extended with the hazard contract and eight new refusal codes |
| `forensics/tools/etp_t1_seed.py` | projects the register into the T1 graph |
| `evidence/etp-t1/TRACEABILITY.json` | regenerated: 325 nodes, 403 edges, 21 declared orphans |
| `forensics/tools/tests/test_traceability.py` | remains 17/17; the declared-origin count is now 21 |
| `docs/REQUIREMENTS-TRACEABILITY.md` | model, counts and refusal codes updated |
| `docs/ETP-TODO.md` | ETP-T2 row; a note on the extended ETP-T1 row |
| `evidence/etp-t2/RECEIPT.md` | this receipt |

## 2. Input classification

Three classes, eight families, each with the guarantee the implementation makes
per class (`docs/HAZARD-REGISTER.md` §1):

| family | class 1 legal | class 2 adversarial, contract-valid | class 3 contract violation |
|---|---|---|---|
| `bn` | checked allocation, defined refusal of even/zero modulus | hostile key or ciphertext, caller-chosen width | `UB_NOT_CLAIMED_SAFE` |
| `rsa` | blinding by default, implicit rejection for an internal key | attacker ciphertext, hostile signature; external-key path has no implicit rejection | `UB_NOT_CLAIMED_SAFE` |
| `ec` | secure nonce scalar, zero rejection | hostile digest, point or signature | `UB_NOT_CLAIMED_SAFE` |
| `evp` | defined return and error; nonce uniqueness is a caller obligation | failed tag or defined parse error | `UB_NOT_CLAIMED_SAFE` or deferred crypto failure |
| `bio` | callback protocol, veto on non-positive pre-call | defined return; the callback is not sandboxed | `UB_NOT_CLAIMED_SAFE` |
| `x509` | depth caps, owned chain snapshot, defined errors | defined parse/verify error under depth and length limits | `UB_NOT_CLAIMED_SAFE`; extension contents unprotected |
| `runtime_mem` | NULL and error on exhaustion, checked size, covered cleansing | checked overflow, NULL where fallible | `UB_NOT_CLAIMED_SAFE`; same-thread ERR re-entry fails closed |
| `provider_dispatch` | refcounts, defined fetch failure | defined fetch or operation error | `UB_NOT_CLAIMED_SAFE` |

**Class-3 statement.** No class-3 input is claimed memory-safe. Seven hazards
are class-3-reachable (`HAZ-04`, `HAZ-06`, `HAZ-13`, `HAZ-14`, `HAZ-18`,
`HAZ-19`, `HAZ-20`); five are class-3-only and sit in fault tree `TE-8`, never
in the class-1/2 corruption tree `TE-4`. The rule is enforced twice:
`TG_HAZARD_CLASS3_SAFE_CLAIM` in the graph validator and
`HR_CLASS3_SAFE_CLAIM` in the register validator. A class-3-reachable hazard
must also state whether the practical behaviour is a defined error, an abort,
undefined-not-claimed, a deferred cryptographic failure, or unreachable; the
register distinguishes a deliberate divergence (`HAZ-13`) from authority parity
(`HAZ-20`) and a stated residual (`HAZ-14`).

## 3. Register counts

| dimension | count |
|---|---|
| hazards | 20 |
| fault trees / top events | 8 |
| FMEA rows | 30 |
| STPA-Sec control-structure nodes / UCAs | 9 / 12 |
| attack graphs | 7 |
| assumptions recorded | 16 |

Hazards by top event:

| top event | hazards |
|---|---|
| TE-1 private-key disclosure | 4 |
| TE-2 signature forgery or verification bypass | 2 |
| TE-3 plaintext disclosure | 3 |
| TE-4 memory corruption from a class-1/2 input | 4 |
| TE-5 denial of service | 3 |
| TE-6 silent wrong result | 3 |
| TE-7 loss of constant-time behaviour | 4 |
| TE-8 memory corruption only from a contract violation | 5 |

Hazards by trigger class: legal 8, adversarial-contract-valid 8,
contract-violation 7.

## 4. Barrier state and the `CLAIMED_NO_EVIDENCE` population

| state | hazards |
|---|---|
| `EVIDENCED` | 0 |
| `CLAIMED_NO_EVIDENCE` | 16 |
| `BARRIER_ABSENT` | 4 |

The `CLAIMED_NO_EVIDENCE` population is `HAZ-01`, `HAZ-02`, `HAZ-03`, `HAZ-04`,
`HAZ-05`, `HAZ-06`, `HAZ-07`, `HAZ-08`, `HAZ-09`, `HAZ-10`, `HAZ-11`, `HAZ-12`,
`HAZ-13`, `HAZ-14`, `HAZ-17`, `HAZ-19`. Every one names the control in source
and states what receipt-bound check would close it.

The FMEA population agrees at row level: 22 `CLAIMED_NO_EVIDENCE`, 8 `NONE`, 0
`EVIDENCED`. The `NONE` rows are `FMEA-05` (BN_CTX scratch), `-15` (external-key
oracle), `-16` (blinding release), `-17` (recombination), `-22` (GCM IV reuse),
`-23` (non-BIO `cb_arg`), `-24` (BIO callback frees the BIO), `-26` (in-place
cached-extension mutation).

Zero `EVIDENCED` barriers is the central result. The T1 evidence tier contains
101 records — instrument qualifications, consumer closures, reproducibility
results and queue-status prose — and none of them is a receipt that a control at
one of these components ran and held at the analysis candidate.

### Hazards with no barrier at all

| hazard | why the barrier is absent | what would close it |
|---|---|---|
| `HAZ-15` | On `RSA_FLAG_EXT_PKEY`, PKCS#1 v1.5 decryption substitutes `RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING` and takes the refusing check; the implicit-rejection countermeasure exists only where the private exponent is held | an external-key implicit-rejection design, or a recorded exclusion for every in-scope external-key v1.5 decryption path (`OBL-RSA-EXTKEY-ORACLE`) |
| `HAZ-16` | `guard_ffi` guarantees non-unwinding and states that it cannot repair partially mutated state; there is no failure-atomic, rollback or poison evidence | failure-atomicity, rollback or poisoning for every stateful FFI context (`OBL-PANIC-ATOMICITY`, `OBL-XCUT-PANIC`) |
| `HAZ-18` | `EVP_DigestVerifyFinal` answers 0 for invalid and -1 for error; the C ABI cannot force a consumer to test exactly 1 | a consumer audit of every in-scope verification call site (`OBL-VERIFY-RETURN-POLARITY`) |
| `HAZ-20` | `cb_arg` is `char *` in the header and is cast to `BIO *`; the authority writes through whatever it addresses, and this is reproduced deliberately | a typed callback-argument contract or an explicit refusal recorded as a safety divergence (`OBL-XCUT-CALLBACKS`) |

## 5. Most consequential finding

**The external-key PKCS#1 v1.5 decryption path has no implicit rejection, and
its trigger is a contract-valid attacker input.** An application that registers
a private key held outside the library (`RSA_FLAG_EXT_PKEY`) and decrypts
attacker-submitted v1.5 ciphertexts gets an observable refusal where the
internal-key path would answer a synthetic message. That is a
Bleichenbacher/ROBOT oracle, not a memory-safety defect, and the class-2
classification is what makes it severe: the API's own contract does not let the
register downgrade it. The register records `BARRIER_ABSENT`, adds
`OBL-RSA-EXTKEY-ORACLE`, and that obligation constrains `REL-OPENSSH-B85C`.

The second finding is structural: **no hazard in the admitted surfaces has an
evidenced barrier**, and the T1 evidence tier cannot supply one. Panic safety is
the clearest instance — `src/ffi/mod.rs` says in its own words that the boundary
"promises only not to unwind" and that inconsistent state "is itself the defect
to fix", while `AGENTS.md` §4 requires failure-atomic, rollback or poisoned
state. The requirement exists, the implementation's own documentation disclaims
the guarantee, and no evidence bears on it.

## 6. New controls and observed refusals

`traceability.py` gained the hazard contract; `hazard_register.py` is new. Both
run in every control below.

| control | mutation | observed refusal |
|---|---|---|
| register hazard has no scope | delete `HAZ-08.scope` | `HR_UNSCOPED_HAZARD` |
| register hazard has no input class | empty `HAZ-08.trigger_classes` | `HR_NO_INPUT_CLASS` |
| class-3-only hazard claims memory safety | `HAZ-04.memory_safe_claim = true` | `HR_CLASS3_SAFE_CLAIM` |
| class-3 hazard has no disposition | delete `HAZ-19.class3_disposition` | `HR_CLASS3_DISPOSITION` |
| tree leaf names neither mechanism nor hazard | strip `TE1-L-BRANCH` | `HR_TREE_LEAF_UNNAMED` |
| tree leaf names an unknown hazard | `TE1-L-BLIND.hazard = HAZ-NOT-REGISTERED` | `HR_TREE_HAZARD_UNKNOWN` |
| FMEA claims an evidenced control with no evidence | `FMEA-01` status `EVIDENCED`, empty list | `HR_FMEA_EVIDENCE` |
| FMEA claimed control cites evidence | `FMEA-01` cites `EVD-INST-ALLOC_PROBE` | `HR_FMEA_EVIDENCE` |
| attack graph claims an evidenced barrier with none | `AG-1` evidenced, empty list | `HR_AG_INCOMPLETE` |
| UCA names an absent controller | `UCA-01.controller = CS-ABSENT` | `HR_STPA_UCA_INCOMPLETE` |
| graph hazard scope drifts from the register | change `HAZ-08.scope` | `HR_GRAPH_FIELD_MISMATCH` |
| graph hazard node is removed | remove `HAZ-08` and its edges | `HR_GRAPH_NODE_MISSING` |
| graph hazard edge is removed | remove `HAZ-02 -> EVD-INST-BINSEC_CHECKCT` | `HR_GRAPH_EDGE_MISMATCH` |
| graph register digest drifts | zero `hazard_register.sha256` | `HR_GRAPH_FIELD_MISMATCH` |
| graph hazard has no scope | delete `HAZ-08.scope` | `TG_HAZARD_UNSCOPED` |
| graph hazard has no input class | empty `trigger_classes` | `TG_HAZARD_NO_INPUT_CLASS` |
| graph class-3-only hazard claims safety | `HAZ-04.memory_safe_claim = true` | `TG_HAZARD_CLASS3_SAFE_CLAIM` |
| graph records `EVIDENCED` with no evidence | `HAZ-08.barrier.state = EVIDENCED` | `TG_HAZARD_BARRIER_UNEVIDENCED` |
| graph hazard has no `motivates` edge | remove `HAZ-18 -> REQ-CORR-01` | `TG_HAZARD_UNMOTIVATED` |
| graph hazard names an unrelated claim | `HAZ-17.affected_release_claims = [REL-CURL-049]` | `TG_HAZARD_CLAIM_UNRELATED` |
| positive control | the committed register and graph | exit 0, "register and traceability graph agree" |
| determinism | `validate` twice | byte-identical stdout and stderr |

Observed gate output:

```
hazard register .../HAZARDS.json: 20 hazards, 8 fault trees, 30 FMEA rows, 12 UCAs, 7 attack graphs
barrier states: BARRIER_ABSENT=4, CLAIMED_NO_EVIDENCE=16, EVIDENCED=0; FMEA evidence: CLAIMED_NO_EVIDENCE=22, EVIDENCED=0, NONE=8
BARRIER_ABSENT: HAZ-15, HAZ-16, HAZ-18, HAZ-20; no release claim: HAZ-05, HAZ-12, HAZ-17
register and traceability graph agree
Ran 23 tests in 0.858s
OK
```

## 7. The T1 graph with the hazards included

`python3 forensics/tools/etp_t1_seed.py` reproduces the committed graph byte for
byte, and `python3 forensics/tools/traceability.py validate` reports:

```
traceability graph at 21bea3188...: 325 nodes (adjudication=41, artefact=26,
evidence=101, hazard=20, implementation=20, obligation=81, release_claim=6,
requirement=22, threat=8); 403 edges (assessed_by=130, constrains=33,
evidenced_by=61, motivates=45, raises=51, realised_by=29, releases=8,
satisfied_by=46)
orphans: 21 declared and reproduced (21 ids), 0 undeclared, 0 stale
```

Changes to the seed:

| addition | edge effect |
|---|---|
| 20 hazards projected from the register | 17 `motivates`, 21 `raises`, 11 `evidenced_by` |
| `REQ-CORR-01` ("a cryptographic result is correct or the operation fails") | 2 `satisfied_by` (`IMP-BN-MONT`, `IMP-RSA`); incoming `motivates` from `HAZ-10`, `HAZ-18`; added to the b85c scope |
| `IMP-BN-MONT` and its file artefact | 2 `satisfied_by`, 1 `realised_by` |
| `OBL-RSA-EXTKEY-ORACLE`, `OBL-PANIC-ATOMICITY` | each constrains `REL-OPENSSH-B85C` |
| `OBL-VERIFY-RETURN-POLARITY` | no release block; no in-scope consumer is shown to mishandle the return |

The orphan register grows from 20 to 21 because `REQ-CORR-01` declares that an
independent specification is required and none exists
(`ORPHAN-6:REQ:REQ-CORR-01`). The classes are still `[1, 3, 6, 8]`; classes 2,
4, 5 and 7 remain zero and are still exercised by their controls.

Three hazards reach no release claim: `HAZ-05`, `HAZ-12`, `HAZ-17`. The graph
derivation is exact — no claim's `scope_requirements` names `REQ-MEM-01`,
`REQ-MEM-02` or `REQ-MEM-03`, and none of the obligations these hazards raise
declares a block. The cause is a scope gap in the claims, recorded rather than
repaired by adding a declaration the claim's record does not contain.

## 8. Obligations and compatibility

- **Unsafe operations:** none added, removed or relocated. `src/`, `docker/`,
  `Cargo.toml`, `Cargo.lock` and the build scripts are untouched.
- **Obligations created:** `OBL-RSA-EXTKEY-ORACLE`, `OBL-PANIC-ATOMICITY`,
  `OBL-VERIFY-RETURN-POLARITY`, all `OPEN`. Two constrain `REL-OPENSSH-B85C`.
- **Obligations discharged:** none. All 81 obligation nodes remain `OPEN`.
- **Compatibility:** not affected; no library artefact changed. The graph's
  declared scope for `REL-OPENSSH-B85C` is widened to include `REQ-CORR-01`,
  which narrows the claim rather than supporting it.
- **STOP conditions:** none triggered in the sense of a corroborated new
  memory-safety defect. `HAZ-20` records a documented, deliberately reproduced
  write-through-a-cast, and `HAZ-15` records an absent cryptographic barrier;
  neither is repaired here, and neither is softened.

## 9. What this does not establish

- **No barrier is shown to work.** `EVIDENCED = 0`; the register's positive
  statements are about scope and trigger class, not about effectiveness.
- **Population completeness is `UNKNOWN`.** There is no frozen expected-hazard
  manifest, so the register cannot prove it lists every hazard in the eight
  families. The same limitation the ETP-T1 receipt records for requirements
  applies here.
- **The timing assumptions are assumptions.** `ASM-TIMING-OBSERVER`,
  `ASM-DRBG-COMPROMISE` and the fault-injection assumption are recorded, not
  measured. No constant-time claim is made.
- **The class-3 dispositions are not safety cases.** They state what happens in
  practice for the named trigger and whether the behaviour is deliberate; they
  do not make the class safe.
- **No release claim is adjudicated.** The register adds obligations to claims;
  it does not decide them. The b85c reconciliation remains ETP-T15's work.
- **No `src/` fix is attempted.** A defect found by analysis is recorded as a
  hazard and an obligation; the change that would close it is named, not made.

## 10. Commands

All Python ran in the court:

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 OPENSSL_RS_COURT_MEM=6g \
OPENSSL_RS_COURT_MEMSWAP=6g bash docker/openssl-rs-court.sh exec sh -c '
  cd /work &&
  python3 -m json.tool evidence/etp-t2/HAZARDS.json >/dev/null &&
  python3 forensics/tools/etp_t1_seed.py &&
  python3 forensics/tools/traceability.py validate &&
  python3 forensics/tools/hazard_register.py validate &&
  python3 forensics/tools/tests/test_traceability.py &&
  python3 forensics/tools/tests/test_hazard_register.py'
```
