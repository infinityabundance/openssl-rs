# Transparency non-claims

Status: **public statement of properties this repository does not claim.**

This document exists because §B.29 of `docs/ETP-ADDENDUM-B.md` makes external
transparency work a condition of a SEAL claim, not a decoration:

> **SEAL** — "complete required external publication, trusted timestamping,
> inclusion and consistency verification, witness-policy evaluation, archival,
> release reconciliation"

and because the EXTERNAL tier is independently owned:

> **EXTERNAL** — "independent parties publish their own authenticated review and
> reproduction results"

Every one of those obligations is **not met in this venue**. A reader who sees a
bundle, a statement digest, a fixture log or a passing release gate may infer
that one of them is met. The list below states, for each, that it is not, and
names the record that shows the absence. It is the complement of the §B.29 SEAL
and EXTERNAL rows: what those rows require and this repository does not have.

The list is enforced. `forensics/tools/continuous_enforcement.py` refuses a
tree whose public non-claims omit any row (`CE_REFUSED_NONCLAIMS_ABSENT`), and
release-gate item 10 calls it. The row markers are the check's input, so a
deleted row is a refused release, not a documentation edit.

| # | property not claimed | the record that shows it | the §B.29 obligation it would satisfy |
|---|---|---|---|
| 1 | **no admitted Rekor service** | `evidence/b0/REGISTRY.json`: `serviceReachable: false`, `summary.installed: 0`, `summary.executable: 0`; `evidence/b4/PUBLICATION.json`: `admittedService: false`, `endpoint: null` | SEAL "complete required external publication" |
| 2 | **no witness** | `evidence/b5/WITNESSES.json`: `witnesses: 0`, `operators: 0`, `witnessKeys: 0`, `cosignatures: 0`, `code: MN_REFUSED_NO_WITNESS`, `outcome: NOT_RUN` | SEAL "witness-policy evaluation" |
| 3 | **no trusted timestamp** | `evidence/b2/TOKENS.json`: `tokensFound: 0`, `noToken: 5`; `evidence/b2/VERIFICATION.json`: `trusted: 0`, `rootAdmitted: 0` | SEAL "trusted timestamping" |
| 4 | **no publication** | `evidence/b4/PUBLICATION.json`: `published: 0`, `externalVerification: PENDING`; `evidence/b4/VERIFICATION.json`: `externalVerification: NOT_RUN` | SEAL "complete required external publication", "archival", "release reconciliation" |
| 5 | **no independent reproduction** | `evidence/b4/VERIFICATION.json`: `externalVerification: NOT_RUN`; `evidence/b4/PUBLICATION.json`: `externalVerification: PENDING`; `evidence/b7/REFINEMENT.json` `notRun` BM-NR6 records that no independent reviewer or distinct trust domain ran | EXTERNAL "independent parties publish their own authenticated review and reproduction results" |

## What each row means

1. **No admitted Rekor service.** A pinned release tag, a recorded asset digest
   and a local `FIXTURE-1` log are not a service. B0 records 14 pinned
   components, 0 installed and 0 executable, and no tracked path names a Rekor
   endpoint or log key. B4 records `admittedService: false` and no endpoint.
2. **No witness.** B5 evaluates the witness policy against an inventory of zero
   operators, zero keys and zero cosignatures and returns `NOT_RUN`. No
   cosignature exists, so no witness-dependent property is established.
3. **No trusted timestamp.** No RFC 3161 token exists in the tree. B2 records
   zero tokens for all five real artefacts and `trusted: 0`; an imprint match
   would still not be a trusted time.
4. **No publication.** B4 records a *publishable* bundle and a profile that is
   not admitted; `published` is `0`. A publishable bundle is not a published
   one.
5. **No independent reproduction.** Every verification in B1, B2, B3, B4, B5,
   B6 and B7 was run by this repository, with its own fixtures and, where a key
   is needed, a test-only key. No external party ran the verifier.

## What this document does not say

It does not say the statements, bundles and fixtures are worthless. They are
the local evidence B1–B7 record. It says that **no external transparency
property follows from them**, and that the release gate's passing items do not
create one: a gate that passes proves the named machinery accepted the
candidate, not that a log published it (`docs/CONTINUOUS-ENFORCEMENT.md`).

It also does not say these properties are impossible to obtain. Each row names
the record that would change when the property becomes established, and the
release gate refuses a claim that asserts publication or admission while that
record still says `published: 0` / `admittedService: false`
(`CE_REFUSED_PUBLICATION_CLAIM`, `CE_REFUSED_PROFILE_NOT_ADMITTED`).

## `NOT_RUN`

* An admitted public Rekor v2 service, its log key and its inclusion proofs.
* A witness cosignature from an independent operator.
* A trusted RFC 3161 timestamp and its authority chain.
* A published release and the archival record that follows it.
* An independent party's reproduction and authenticated review.
* Any network access, download, install or service configuration.

These are `NOT_RUN`, not `PASS`. They are not converted into a pass by this
document, by a bundle, or by a green release gate.
