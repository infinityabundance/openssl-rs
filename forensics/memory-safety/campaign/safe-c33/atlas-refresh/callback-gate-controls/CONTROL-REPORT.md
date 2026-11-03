# Callback enumeration gate — control report

Date: 2026-11-03. Candidate source: `38a1548be633f3d1be4e55330cbdcb29ef0b8de8`;
inventory source head: `a8716b4f2112bde03c97db5ff7bd1caf3a483c35`;
`src/` unchanged vs that head: `True`.

## Instrument

`forensics/tools/callback_enumeration_gate.py` enumerates `X509V3ExtMethod`
registrations **by slot**, not by callback-name prefix, binds each registration
to a dispatcher path, classifies reachability against
`evidence/closure-ssh-b52-applied.json`, and fails unless every gated callback is
in the obligation inventory or is `PROVEN_EXCLUDED` with a written assumption.
It also walks the six-prefix definition census so callbacks that no row installs
cannot escape. Outputs:

- `callback-registration-manifest.json` (index; includes every row and slot) +
  `callback-registration-manifest/` (registration parts by slot)
- `callback-gate-report.json`
- `callback-enrolment-blockers.json`
- `callback-gate-controls/control-results.json`

## Authoritative result

**FAIL**, exit `1`. Missing entries: **66**
(65 distinct names). Classification:
`PROVEN_REACHABLE=135`,
`PROVEN_EXCLUDED=0`,
`UNRESOLVED=0`.
Inventory-matched callbacks: `69`.
Registrations: `113` slot registrations
across `72` parsed rows, plus
`36` definition-only callbacks;
`135` distinct gated callbacks.

Reconciliation of the 114-definition finding: `115`
six-prefix definitions (`114` distinct names);
`51` already in the queue;
`64` absent entries
(`30` slot registrations,
`34` definition-only helpers).
The gate adds `2` `ext_free`
callbacks, giving `66` enrolments.

## Controls

| Control | Procedure | Command (abridged) | Observed | Verdict |
|---|---|---|---|---|
| **C1** omission | Real source: append `i2s_fixture_probe`, register it in `ossl_v3_fixture_probe`, add the row to `STANDARD_EXTS`; do not add it to the control inventory. Restore with `git show HEAD:path`. | `/usr/bin/python3 forensics/tools/callback_enumeration_gate.py --root /mnt/1tb_kingston/openssl-rs --closure evidence/closure-ssh-b52-applied.json --out-dir forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/out-c1 --manifest-name manifest-c1-added.json --report-name report-c1-added.json --enrolment-name enrolment-c1-added.json --inventory forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/inventory-post-enrolment.json --allow-source-drift` | baseline PASS; added run exit `1` and named `src/x509/v3_skid.rs::i2s_fixture_probe` = `True`; restore byte-identical = `True`; restored PASS = `True` | **PASS** |
| **C2** excluded | One callback (`s2i_skey_id`) dropped from the control inventory; mark it `PROVEN_EXCLUDED`. Run with an empty assumption and with a written assumption. | `/usr/bin/python3 forensics/tools/callback_enumeration_gate.py --root /mnt/1tb_kingston/openssl-rs --closure evidence/closure-ssh-b52-applied.json --out-dir forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/out-c2 --manifest-name manifest-c2-empty.json --report-name report-c2-empty.json --enrolment-name enrolment-c2-empty.json --inventory forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/inventory-minus-s2i_skey_id.json --overrides forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/overrides-excluded-empty.json --allow-source-drift` / `/usr/bin/python3 forensics/tools/callback_enumeration_gate.py --root /mnt/1tb_kingston/openssl-rs --closure evidence/closure-ssh-b52-applied.json --out-dir forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/out-c2 --manifest-name manifest-c2-assumption.json --report-name report-c2-assumption.json --enrolment-name enrolment-c2-assumption.json --inventory forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/inventory-minus-s2i_skey_id.json --overrides forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/overrides-excluded-assumption.json --allow-source-drift` | empty assumption exit `1`, flagged = `True`; written assumption exit `0`, pass = `True` | **PASS** |
| **C3** unresolved | Same dropped callback, marked `UNRESOLVED`. | `/usr/bin/python3 forensics/tools/callback_enumeration_gate.py --root /mnt/1tb_kingston/openssl-rs --closure evidence/closure-ssh-b52-applied.json --out-dir forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/out-c3 --manifest-name manifest-c3-unresolved.json --report-name report-c3-unresolved.json --enrolment-name enrolment-c3-unresolved.json --inventory forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/inventory-minus-s2i_skey_id.json --overrides forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-gate-controls/overrides-unresolved.json --allow-source-drift` | exit `1`, named in `unresolved` = `True` | **PASS** |
| **C4** determinism | Run the authoritative gate twice into the deliverable directory. | `/usr/bin/python3 forensics/tools/callback_enumeration_gate.py --root /mnt/1tb_kingston/openssl-rs --closure evidence/closure-ssh-b52-applied.json --out-dir forensics/memory-safety/campaign/safe-c33/atlas-refresh` (twice) | report sha256 `7f38381f13ac7b344ab5043de699e778cb547541bbf4f467b6e030b6268f3dc6` / `7f38381f13ac7b344ab5043de699e778cb547541bbf4f467b6e030b6268f3dc6`; manifest sha256 `5a44cb3f66abfacc091379981448357a21eb5ac2b28a4f48fb29979f80b2531d` / `5a44cb3f66abfacc091379981448357a21eb5ac2b28a4f48fb29979f80b2531d`; identical = `True` | **PASS** |
| **C5** no false positives | Check every inventoried callback against the missing list. | authoritative run | inventory-matched `69`; reported missing `0`; 51 prefix-named queue callbacks accounted | **PASS** |

C1 uses the real source tree and a **control-only post-enrolment inventory**
(`callback-gate-controls/inventory-post-enrolment.json`: the 312 queue
obligations plus the 66 enrolment records). That inventory is not an applied
census and is not used for the authoritative result. C2/C3 use the same
inventory with `s2i_skey_id` removed, which creates the one-callback gap those
controls need.

## Limitations

- The gate proves **inventory-vs-source agreement** for the registrations and
  six-prefix definitions it parses. It does not prove that macro-generated or
  build-script-generated rows were parsed.
- Dispatcher bindings are source-level `STANDARD_EXTS` / call-site witnesses;
  they are not execution proofs. `PROVEN_REACHABLE` via a reachable dispatcher
  means the row is dispatchable through that path, not that a consumer input
  exercises it.
- `PROVEN_EXCLUDED` carries closed-world assumption CE-1, stated in each
  record; it is scoped to the pinned consumer family and is not a general
  property of the callback.
- The gate does not adjudicate safety and changes no obligation status. The 66
  enrolment records are **proposals**; enrolment is not performed here.

## Reproduce

```sh
python3 forensics/tools/callback_enumeration_gate.py \
  --root . --closure evidence/closure-ssh-b52-applied.json
python3 forensics/tools/callback_gate_controls.py
```

The harness refuses to edit a dirty `v3_skid.rs`/`v3_lib.rs`, restores C1 with
`git show HEAD:<path>`, and verifies `git diff --quiet`. Per-run reports are
regenerated under `callback-gate-controls/out-c*/`; they are pruned from the
committed tree but the receipts above record every observed exit code and
named finding.
