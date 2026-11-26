# PFP-34 — a verified branch audit is a release-admission condition

**State: DONE.** The release gate has an eleventh item that reads a recorded
binary branch-audit result bound to the candidate's source and DSO. It refuses an
unresolved secret-derived conditional transfer, a secret-derived memory address,
an uncovered secret-bearing path, a record measured at another DSO, and a record
whose tool, inventory or coverage binding is stale. Its self-test includes a
deliberately branchy canary record that is refused and the repaired record that is
accepted.

This record is the gate-side admission, not a new measurement. The measurement is
PFP-31's repaired audit at DSO `43a23e9b…`; this item makes that result a condition
a future release must meet rather than an experiment that can be forgotten.

## 1. The gap this closes

PFP-31 repaired the ML-KEM implicit-rejection mask and verified the repair in the
release DSO. Nothing in the release gate read that result: a later candidate could
reintroduce the same conditional transfer, or ship a secret-bearing path the audit
never covered, and the ordinary checks would remain green. PFP-34 makes the
recorded audit an admission condition.

## 2. Interface used

`forensics/tools/release_gate.py` item 11 (`check_branch_audit`). It **reads a
recorded result**; it does not rebuild, disassemble or run the audit inside the
gate. The reasons are the same ones that make the gate cheap and fail-closed:

- the DSO is a build artefact, not a tracked input, so the gate cannot regenerate
  it from the candidate without a build and a court budget;
- `courts/phase18/timing/binary_branch_audit.py` is a review instrument whose
  digest is part of the record, so a recorded result carries its own instrument
  identity;
- a recorded result can bind the exact DSO sha256, the target inventory and the
  coverage requirement, which a live re-run of a different DSO would not.

The record is `evidence/performance-frontier/campaigns/PFP-34/audit-record.json`.
It names the PFP-31 repaired candidate (`c34cfe62f`, tree
`fee211d0685938cc9281f8d79e50a7b24fc21617`), DSO
`43a23e9b7b4628cb236d75bb8bc4b73583a035f3335bd0244f1771e81b773557`, and binds
the audit tool (`5d54f3a1…`), the inventory (`targets-pfp31.json`, `3a7f5697…`)
and the coverage requirement (`02d92c10…`) by digest. The per-target fields are
transcribed from the recorded audit at
`PFP-31/repair-raw/audit-repaired.md` / `.stderr` (digests in the record).

## 3. Refusal codes

| code | refuses |
|---|---|
| `RG_AUDIT_RECORD_MISSING` | no recorded audit result at the record path |
| `RG_AUDIT_RECORD_INVALID` | unreadable/schema-wrong record, a target with no stated classification, or a recorded audit that exited non-zero / refused a target |
| `RG_AUDIT_STALE_BINDING` | the record's audit-tool, inventory or coverage digest does not match the committed file, or a coverage source changed |
| `RG_AUDIT_IDENTITY_MISMATCH` | the record was measured at another candidate/tree, or a caller-declared candidate DSO digest differs from the recorded one |
| `RG_AUDIT_SECRET_BRANCH` | a secret-derived `jcc`, or a secret-derived `setcc` consumed as a control condition |
| `RG_AUDIT_SECRET_ADDRESS` | a secret-derived memory address, including a secret-derived `cmov` whose operand address is variable |
| `RG_AUDIT_CMOV_UNQUALIFIED` | a secret-derived `cmov` whose record does not state register or fixed-address operands, or does not state that it is transfer-free |
| `RG_AUDIT_UNCOVERED_PATH` | a path the project claims audited has no target in the record, or the coverage requirement is absent |

The three flag readers are treated differently on purpose. A secret-derived `jcc`
is a transfer. A secret-derived `setcc` consumed arithmetically writes a value and
is not a transfer. A secret-derived `cmov` is accepted only with **register** or
**fixed-address** operands and a **fixed** condition address; the record must say
which. The recorded repaired `key::decap` has one secret-derived `setcc`
(`0x1d3675 setne %al`, consumed arithmetically) and one secret-derived `cmov`
(`0x1d3696 cmovne %rcx,%rdx`, register operands, fixed stack address), and the
recorded `arith::scalar_ntt` has 14 register-to-register `cmov`s; all are
transfer-free under this rule.

## 4. Coverage requirement and its source

`evidence/performance-frontier/campaigns/PFP-34/coverage.json` records the
secret-bearing paths the project claims audited and the targets that must appear
for each. Its sources are:

- `evidence/performance-frontier/campaigns/PFP-29/CHECKPOINT.md` §3
  (“Coverage by path”, digest `174f10b1…`) — the nine per-path populations;
- `evidence/performance-frontier/campaigns/PFP-31/targets-pfp31.json`
  (digest `3a7f5697…`) — the targets that reach each path.

Eight paths are secret-bearing and required: `ecdsa-sign`,
`ecdsa-sign-default`, `ecdh`, `rsa-crt`, `rsa-nocrt`, `rsa-crt-pkcs1`, `dh`,
`mlkem-decaps`. `ecdsa-verify` is public-only (public key, published signature,
public digest) and is recorded as such, not required. PFP-31 closed the two gaps
the PFP-29 table named (`key::decap`, `arith::scalar_ntt`), so **no required path
is uncovered today**.

The gate verifies the coverage source digests; a changed PFP-29 table or inventory
makes the binding stale rather than silently narrowing coverage. A path listed
with no target is `RG_AUDIT_UNCOVERED_PATH`.

## 5. The gate's own control (self-test)

`python3 forensics/tools/release_gate.py --self-test` — **40 cases**, of which 6
are this item:

| case | expected |
|---|---|
| repaired branch-audit record | no refusal (positive control) |
| branchy canary audit record (the pre-repair `key::decap` `jcc` at `0x300613`) | `RG_AUDIT_SECRET_BRANCH` |
| audit record for another DSO | `RG_AUDIT_IDENTITY_MISMATCH` |
| uncovered secret-bearing path (`arith::scalar_ntt` removed) | `RG_AUDIT_UNCOVERED_PATH` |
| secret-derived `cmov` without recorded operands | `RG_AUDIT_CMOV_UNQUALIFIED` |
| secret-derived memory address | `RG_AUDIT_SECRET_ADDRESS` |

The canary is the same record with the secret-derived `jcc` restored. If a later
change makes the gate accept it, the self-test fails. The repaired record is
accepted only against its own candidate and DSO.

## 6. Observed gate output

`python3 forensics/tools/release_gate.py` at `staging 9488e1061`, worktree with
this change uncommitted:

```
release-gate: REFUSED (36 item(s))
```

Per-code counts (baseline 35 → 36):

| code | before | after |
|---|---:|---:|
| `RG_CLAIM_UNCERTIFIABLE_EVIDENCE` | 19 | 19 |
| `RG_CLAIM_HISTORICAL_EVIDENCE` | 11 | 11 |
| `RG_THRESHOLD_UNMET` | 1 | 1 |
| `RG_POLICY_DENIED` | 1 | 1 |
| `RG_PACKAGE_MISSING` | 1 | 1 |
| `RG_INSTRUMENT` | 1 | 1 |
| `RG_AUTHORISATION_REFUSED` | 1 | 1 |
| `RG_AUDIT_IDENTITY_MISMATCH` | — | **1** |

The single added refusal is the item working: the only committed audit record is
for source `c34cfe62f` / DSO `43a23e9b…`, and the gate candidate is `9488e1061`
(tree `79782350…`). A result measured at another DSO cannot evidence this
candidate; a candidate must carry its own record.

## 7. What this enforces and what it does not

Enforced: a candidate with no matching record is refused; a record reporting a
secret-derived conditional transfer or memory address is refused; a claimed path
with no target is refused; the record cannot be silently re-pointed at another
DSO, tool, inventory or coverage list.

Not enforced: the gate does not itself taint-analyse the DSO. It reads the
classification the record contains. For `key::decap` the record carries a
per-instruction comparison-contract classification; for the other targets the
record is the per-target instruction inventory plus the reviewer's source
classification and must be re-derived when the audit is re-run
(`classification: "inventory-and-source-review"`). A cmov count is not, by
itself, a taint result; the record says so and only the classified cmovs are
listed. The gate is an admission rule over recorded evidence, not a constant-time
proof and not a substitute for the audit.
