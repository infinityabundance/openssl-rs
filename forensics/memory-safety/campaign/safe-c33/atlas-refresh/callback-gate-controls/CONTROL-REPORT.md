# Callback enumeration gate — control report

Date: 2026-11-03. Candidate source: `f2a8110cdc7dc94cc6cf5a3af92bd7c3c234a04f`;
inventory source head: `a8716b4f2112bde03c97db5ff7bd1caf3a483c35`;
`src/` unchanged vs that head: `True`.
Instrument sha256: `648ecd9b00d9941746a73558f96d3ea60fc9b01142a54eda92b0367ed12966a6`.

## Vocabulary

`REACHABLE_BOUND` is a **may-bound, not a proof**. Each record carries exactly
one `basis`:

| basis | meaning |
|---|---|
| `edge-witness` | a concrete source call-graph edge from a caller that is itself reachable-bound; the record carries caller, callee and site |
| `module-name-match` | membership in the closure `reachable_functions` set, module-qualified; may-bound |
| `unique-name-match` | membership by a globally unique name; may-bound |
| `dispatcher-row-binding` | `STANDARD_EXTS` row plus a reachable dispatcher; **no callback symbol** was found in the reachable set |

Registration counts: `edge-witness=38`,
`module-name-match=104`,
`unique-name-match=0`,
`dispatcher-row-binding=7`.
Per-definition callback counts: `{'dispatcher-row-binding': 7, 'edge-witness': 37, 'module-name-match': 91, 'unique-name-match': 0}`.

## Authoritative result

**FAIL**, exit `1`. `REACHABLE_BOUND`
`135`; `PROVEN_EXCLUDED`
`0`; `UNRESOLVED`
`0`. Missing:
**66 entries / 65 distinct names**
(units: entries are per file-qualified callback definition). Inventory
accounted: `69`.

Reconciliation: `115` six-prefix definitions
(`114` names); `51`
in the queue; `64` absent entries
(`30` slot registrations,
`34` definition-only);
plus `2` `ext_free` = `66`.

### Per-definition check

`compute_callback_reach` operates on `(file, definition line, item)`.
`i2r_ISSUER_SERIAL` is two distinct results:
`src/x509/v3_ac_tgt.rs:624` (edge from `i2r_TARGET_CERT` at `:840`) and
`src/x509/v3_authattid.rs:164` (edge from `i2r_auth_attr_id` at `:247`).

## Controls

| Control | Procedure | Observed | Verdict |
|---|---|---|---|
| **C1** omission | Real source: add `i2s_fixture_probe`, register it, add the row to `STANDARD_EXTS`; restore with `git show HEAD:path`. | baseline PASS; added exit `1` and named = `True`; restore byte-identical = `True`; restored PASS = `True` | **PASS** |
| **C2** excluded | `s2i_skey_id` dropped; `PROVEN_EXCLUDED` with empty vs written assumption. | empty exit `1`, flagged `True`; written exit `0`, pass `True` | **PASS** |
| **C3** unresolved | Same callback marked `UNRESOLVED`. | exit `1`, flagged `True` | **PASS** |
| **C4** determinism | Authoritative run twice. | report `b900e24e8db67b5221d3d3d290af930e4b85698903e680274b991a612aa33ef3` / `b900e24e8db67b5221d3d3d290af930e4b85698903e680274b991a612aa33ef3`; manifest `e34d1e92179959acb215f047f77cc161345fd012c22f666459a770525ce2bdcb` / `e34d1e92179959acb215f047f77cc161345fd012c22f666459a770525ce2bdcb`; identical `True` | **PASS** |
| **C5** exact accounting | Assert exactly 69 inventoried callbacks accounted for, none unaccounted, no slot-prefix inventory callback unseen; then drop `skid_i2s` from the authoritative inventory. | accounted `69`; unaccounted `[]`; loss accounted `68`, exit `1` | **PASS** |
| **C6** fresh out-dir | Run with a nonexistent `--out-dir` (harness does not pre-create it). | exit `0`, report written `True` | **PASS** |

C1/C2/C3/C6 use a **control-only post-enrolment inventory**
(`callback-gate-controls/inventory-post-enrolment.json`), not an applied census.
C5's loss run uses the authoritative inventory minus `skid_i2s` only.

## Limits

- The gate proves inventory-vs-source agreement for parsed registrations and
  six-prefix definitions; macro/build-script-generated rows are outside it.
- `REACHABLE_BOUND` is a may-bound. Only `edge-witness` records a concrete
  call edge, and even that edge's caller may itself be reachable-bound.
  `module-name-match`/`unique-name-match` rest on the closure's converged
  MAY-bound set; `dispatcher-row-binding` is a table witness, not execution.
- `PROVEN_EXCLUDED` carries closed-world assumption CE-1, scoped to the pinned
  consumer family.
- The gate changes no obligation status. The 66 entries are proposals; enrolment
  is not performed here.

## Reproduce

```sh
python3 forensics/tools/callback_enumeration_gate.py --root . \
  --closure evidence/closure-ssh-b52-applied.json
python3 forensics/tools/callback_gate_controls.py
```
