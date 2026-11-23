# Phase-18 hardening seal — erratum (ETP-T15)

**Status:** correction of three numeric statements in
`docs/PHASE-18-HARDENING-SEAL.md`. The seal is retained unchanged as the record
of what was asserted at its own date; this erratum states the tracked values and
names which side is wrong.

**Authority:** the tracked records it cites, at the source identity the seal
names. `artifacts/phase18/COURTS.json` and `forensics/phase18-obligations.json`
are the measurement records; the seal prose is a description of them.

**Reconciliation item:** `ETP-T15`. Machine record:
`evidence/etp-t15/RECONCILIATION.json`.

---

## 1. Court registry

The seal's preamble (§0, "Court results") states:

> `artifacts/phase18/COURTS.json` — five courts, `all_pass` true, `summary` `pass`
> 5 of 5, `pending_courts` empty

The tracked record at the seal's own source identity states:

| field | seal prose | tracked `body` | verdict |
|---|---|---|---|
| `all_pass` | `true` | `false` | the prose is wrong |
| `summary` | pass 5 of 5 | `{"pass": 4, "fail": 1, "total": 5}` | the prose is wrong |
| `pending_courts` | empty | `{}` (empty) | agrees |

The failing court is `HOSTILE-BOUNDARY-REGISTER`, whose row reports `fail` with
56 `UNSAFE-FOOTPRINT` bound violations (for example `bn` 1170 -> 1357, `evp`
8029 -> 8798, `ssl` 3503 -> 4407). The measurement ran; it reports a failure.
The prose reports the opposite. **The measurement is not wrong; the prose is.**

## 2. Obligation ledger

The seal's preamble (§0, "Obligation ledger") states:

> `forensics/phase18-obligations.json` — `owned` 5, `implemented` 5,
> `deferred_to_later_phase` 0, `open_in_this_stratum` 0

The tracked record states:

| field | seal prose | tracked `body.counts` | verdict |
|---|---|---|---|
| `owned` | 5 | 5 | agrees |
| `implemented` | 5 | 4 | the prose is wrong |
| `deferred_to_later_phase` | 0 | 0 | agrees |
| `open_in_this_stratum` | 0 | 1 | the prose is wrong |
| `contract_units` | 5 | 5 | agrees |

The open unit is `hostile-boundary-register`: its `measurement_state` is
`not_measured`, its `state` is `open`, and its `observation` is
`HOSTILE-BOUNDARY-REGISTER is fail`. The ledger reports one open contract unit.
**The measurement is not wrong; the prose is.**

## 3. CT-PRIMITIVES separation threshold

The seal states the separation threshold as:

- 110 percent in §18.3 ("exceeds 110");
- a 50 percent floor in §0's non-claims and §6 ("a 50 percent floor");
- 150 percent in §6.3 and §18.3's summary ("exceeds 150 percent").

The executable measurement states 150 percent in both places:

| record | field | value |
|---|---|---|
| `courts/phase18/ct_primitives_probe.c` | `SEP_PCT` | `150` |
| `artifacts/phase18/COURTS.json` | `threshold_percent` | `150` |

The probe source and the machine threshold agree at 150 percent. The seal prose
is internally inconsistent. **The measurement is self-consistent; the prose is
wrong on 110 and on the bare 50 percent floor.**

One additional defect is recorded and not repaired: `artifacts/phase18/COURTS.json`
carries a descriptive `claim` field that still states 50 percent while its own
`threshold_percent` field states 150. That is a **record defect in a descriptive
field**, not a measurement defect. The machine field `threshold_percent` and the
probe agree; the `claim` prose does not. The artefact is not rewritten, because
a measurement record is not edited to make its prose agree.

## 4. What this erratum does not decide

- It does not re-run any Phase-18 court. The values are those the tracked
  records already contain at the seal's source identity.
- It does not turn the failing court into a passing one, or the open unit into a
  closed one. `HOSTILE-BOUNDARY-REGISTER` remains a recorded failure and
  `hostile-boundary-register` remains an open contract unit.
- It does not establish any constant-time property. A `CT-PRIMITIVES` pass is
  the instrument's proven sensitivity plus a bounded result; the seal's own
  non-claims on that point remain accurate.
- It does not review the seal's other statements, which this reconciliation did
  not find contradicted by the tracked records.
- It does not claim that the Phase-18 stratum is complete, or that any claim
  derived from it is established.

## 5. Effect on the typed claims

`ETP0-CLM-004` and `ETP0-CLM-005` were typed `CONTRADICTED` because the seal
prose and the tracked records disagreed. This erratum identifies the prose as
the wrong side, which is exactly what those claims recorded. The claims are
therefore `SUPERSEDED` by the reconciliation — not promoted, not `ESTABLISHED` —
and their original parties remain in `evidence/etp-t15/history/`.
