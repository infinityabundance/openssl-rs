# A0 — Evidence and trust-surface audit: receipt

Item: **A0 of `docs/ETP-TODO.md` (ETP Addendum A)**.
Kind: contract analysis and inventory. **No repair was made.** No file under
`src/`, `docker/`, `courts/` or another item's evidence was modified.

## 1. Candidate

| field | value |
|---|---|
| branch | `staging` |
| commit | `e0b727d067b00da65ff66f329a36c725bc2658e5` |
| worktree at start | clean (0 tracked or untracked changes) |
| tracked files | 14,241 |
| git object format | `sha1` |

The candidate was read only. Every count in the deliverables was recomputed from
this commit; no receipt figure was copied without recomputation.

## 2. Environment (§6.1)

| field | value |
|---|---|
| `free -g` available | 19 GiB |
| derived cap | `min(8, 19 − 16) = 3g`; the 2g floor is met |
| court | `docker/openssl-rs-court-tools:1`, `OPENSSL_RS_COURT_MEM=3g`, `OPENSSL_RS_COURT_MEMSWAP=3g` |
| heavy commands | all under the court; one at a time; no build, no test suite, no benchmark |
| parallelism | Python-only reads over tracked JSON; no compiler invocation |

No build was attempted. The §6.1 floor of 24 GiB available before a build was
not reached, so no build was permitted or run.

## 3. Deliverables

| artefact | purpose | validation |
|---|---|---|
| `docs/EVIDENCE-AUDIT.md` | inventory, four defect classes, ranking, sound set, limits, handoff | prose reviewed against the machine records |
| `evidence/a0/INVENTORY.json` | 25 artefact records, 8 absent formats, 42 summary counts | `python3 -m json.tool` exit 0 |
| `evidence/a0/FINDINGS.json` | 18 findings in four classes, ranking, sound set, limits, handoff | `python3 -m json.tool` exit 0 |
| `evidence/a0/RECEIPT.md` | this record | — |
| `docs/ETP-TODO.md` | A0 row updated from `TODO` | row text only |

## 4. What was examined

| population | count |
|---|---|
| tracked files / tracked `.json` / tracked `.md` | 14,241 / 3,131 / 225 |
| distinct `schema` identifiers | 528 |
| evidence JSON files (8 without a `schema` key) | 352 |
| documents in `docs/` | 97 |
| claim set / open obligations / discharged obligations | 35 / 37 / 5 |
| interop receipts / manifests | 14 / 3 |
| freshness artefacts / edges / exclusions | 331 / 5,183 / 228 |
| traceability nodes / edges / declared orphans | 361 / 475 / 43 |
| hazards / FMEA / UCAs / attack graphs | 20 / 30 / 12 / 7 |
| unsafe sites / operation rows | 62,297 / 767 |
| closure rows / opaque-operation rows | 1,121 / 55 |
| scheduling change sets / requirements | 6 / 78 |
| aggregates audited / refused | 8 / 2 |
| instruments | 11 |
| atlas runs / specimens / recipes / reused families | 2,000 / 226 / 307 / 301 |
| external-package inputs / refusals | 1,633 / 5 |

## 5. Findings

Eighteen findings, assigned to the class the defect primarily belongs to:

| class | count | identifiers |
|---|---|---|
| truncation | 4 | F01–F04 |
| silent suppression | 5 | F05–F09 |
| summary without reconstruction | 5 | F10–F14 |
| wrong-candidate application | 4 | F15–F18 |

The three ranked first, with the consequence of trusting each:

1. **F15** — `evidence/etp/claims.json` `ETP0-CLM-032` `OBL-GAP-005`: a
   `DISCHARGED` obligation states that `CAMPAIGN-STATUS.json` records 0/33, while
   the claim's own evidence digest `abb8a6cb…` is the blob at S that records 1.
2. **F01** — `evidence/closure-curl-049.json` `precision.residual_sites`: 200
   member rows against a recorded 449 reachable unresolved and 219
   target-bounded, with no bound field.
3. **F06** — `evidence/etp7/RECEIPT.md` lines 108-156: the only verbatim
   full-gate run records four `RG_CLAIM_CONTRADICTED` refusals and 42 open
   obligations; the live claim set has none and conjoins to 37.

## 6. What is already sound

Eleven mechanisms are named in `docs/EVIDENCE-AUDIT.md` §4 and in
`FINDINGS.json sound`, including: the external-package input digests and refusal
list; the freshness dependency model and its declared exclusions; per-node
traceability digests and the byte-for-byte seed; all 81 claim evidence digests
reconstruct (80 at S, one at the named historical commit `cc2e5fa32`); the
instrument register and its nine executable controls; the O11 derived manifests; the scheduling admission aggregate; the
closure-discipline aggregate refusals; the ETP-T15 reconciliation and history;
the release-gate article mapping; and the independence records. Their identity
binding and reconstruction are adequate and are the model for A2 and A3.

## 7. Obligations

| kind | record |
|---|---|
| discharged | the audit exists at a named candidate with recomputed counts, four populated defect classes, a consequence-ranked top three, a sound set and an explicit limits section |
| retained | every finding is retained for repair; none was reclassified, suppressed or fixed here |
| introduced | none to `src/`, `docker/` or the exported ABI; the new records are `evidence/a0/*` and one queue row |
| deferred | the population checks listed in `docs/EVIDENCE-AUDIT.md` §5 are `NOT_RUN` and are named with the check that would run them |

## 8. Gates run for this item

| check | result |
|---|---|
| `python3 -m json.tool evidence/a0/INVENTORY.json` | exit 0 |
| `python3 -m json.tool evidence/a0/FINDINGS.json` | exit 0 |
| `python3 forensics/tools/etp_claims.py validate` (context check, not a repair) | exit 0, 35 claims, 0 refusals |
| `python3 forensics/tools/etp_claims.py conjoin` (context check) | verdict `SUPERSEDED`, 33 blocked, 37 obligations; this is the current value that F06 compares against the receipt's recorded `CONTRADICTED` / 42 |
| `cargo fmt`, `clippy`, library tests | not run: no Rust source changed and §6.1 forbids a build at 19 GiB available |
| `release_gate.py`, `freshness.py check`, `verify.py all` | not run: A0 does not execute the release or verification machinery it audits; their recorded outputs are the subject, not the instrument |

The two `etp_claims.py` invocations read the existing claim set; they do not
modify it and are not part of the deliverables.

## 9. What this receipt does not establish

- It does not establish that the 18 findings are the complete set of
  misleading records. The populations examined are the ones enumerated in §4;
  the 228 artefacts excluded from freshness tracking by the 512 KiB bound were
  not opened.
- It does not establish that any finding is harmless. Severity ordering is a
  consequence argument in `docs/EVIDENCE-AUDIT.md` §3, not a measured risk.
- It does not establish SARIF, DSSE, in-toto, SLSA, Sigstore or timestamp
  interoperability: those formats are absent, which the inventory records rather
  than treating as a clean result.
- It does not discharge any A1–A27 obligation and does not change any ETP
  verdict. The repairs belong to A1–A7, A17, A20 and A21, and to the owning ETP
  items named in `FINDINGS.json handoff`.
