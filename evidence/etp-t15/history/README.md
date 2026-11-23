# ETP-T15 historical records

Each file here is a byte-for-byte copy of a record taken before the ETP-T15
reconciliation changed the live record. The **copy** is the historical identity;
the live path named beside it is the superseding record.

| file | original path | SHA-256 | identity |
|---|---|---|---|
| `SAFE-COMPATIBLE-openssh-b85c.json` | `evidence/SAFE-COMPATIBLE-openssh-b85c.json` | `41e5797d50bff7b62b25e25184f739bc3d68115396f32c4236d00a14e0301dd2` | the b85c graduation record as issued on 2026-11-17 (`kind: safe-compatible-graduation-record`, `verdict.value: SAFE_COMPATIBLE`) |
| `claims.before-reconciliation.json` | `evidence/etp/claims.json` | `65d8105b744c80ae01e76af8bf3370c478ab116c7fc9b0f16f63eea5d5c579de` | the 35-claim typed set with `ETP0-CLM-004`, `-005`, `-030` and `-032` typed `CONTRADICTED`, each with its original `contradiction.parties` |
| `CAMPAIGN-STATUS.before-reconciliation.json` | `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` | `abb8a6cb6ae4e430bbc8104683909664fad3dfa2dd5dcbc1f8aa69229d16606f` | the ledger with `consumers.safe_compatible = 1`, `safe_compatible_graduation.verdict = SAFE_COMPATIBLE`, and the self-contradicting `consumers.note` |
| `PROGRESS.md` (as `PROGRESS.before-reconciliation.md`) | `forensics/memory-safety/campaign/safe-c33/PROGRESS.md` | `4839a213dddc6f3ced22d539a878dcddf99548dc035cd560a38ebd6bec041a15` | the ledger prose with "The cohort counter is not advanced by it" and the 2026-11-17 record sentence |
| `STATUS-2026-10-20.md` (as `STATUS-2026-10-20.before-reconciliation.md`) | `forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md` | `7c966f896b80f36d2aad665b7deec9dc9377ba301bef581b4983e1ffa18c93ff` | the campaign summary with "The cohort counter is now 1/33" and the `SAFE_COMPATIBLE` consumers row `1/33` |
| `TRACEABILITY.before-reconciliation.json` | `evidence/etp-t1/TRACEABILITY.json` | `d5920c800ad113722d0645b27af0f27e1caee9b2ac596379aa41871be7909e26` | the traceability graph carrying the pre-reconciliation claim verdicts and basis text |

The adjudication (`evidence/b85c-adjudication.json`), the freeze
(`evidence/FREEZE-b85c.json`) and the row reconciliation
(`evidence/b85c-row-reconciliation.json`) were **not changed** by ETP-T15 and
have no copy here; their digests are recorded in
`evidence/etp-t15/RECONCILIATION.json`.

These copies are history. They are not current evidence and must not be cited as
the present state of any record. The current state is the live path, named in
the table's second column, and the reasoning is
`docs/ADJUDICATION-RECONCILIATION.md`.
