# Superseded control records (history)

These files are verbatim copies of the ETP-T3 and ETP-T4 records as they stood
at source candidate `07b776d688fdd1dcc4e315661894c30e623aed9e`. They are kept
so the earlier belief remains inspectable; they are not current evidence.

| file | superseded by | reason |
|------|---------------|--------|
| `SPECIFICATIONS-superseded-07b776d68.json` | `evidence/etp-t3/SPECIFICATIONS.json` | the recorded known-nonconformance token set for `docs/ETP-TODO.md` had 87 tokens; later status notes (ETP-T2, ETP-T6, ETP-T7) added `OPENSSL_clear_free` and `guard_ffi`, so the record drifted from the text |
| `SAFETY-SITES-superseded-07b776d68.json` | `evidence/etp-t4/SAFETY-SITES.json` | the inventory was bound to source tree `b38e0f426c967da4e5433217b6e03b3042bf8773a0cea1dee0d778c637651a7d` (883 files, 910,498 lines); seven later commits changed `src/` to `ef8678c53feb9ec59e8cc61c6a0b636ae59aeb01b6dbe482ebc463932ae2ed1d` (884 files, 915,237 lines) |
| `AXIOMS-superseded-07b776d68.json` | `evidence/etp-t4/AXIOMS.json` | produced by scanner `7b17d4c2b49b8584a0bf7dbfaf98fe84d359e82256a5d01b208675dd1592f3c0` against the superseded source tree |
| `VACUITY-superseded-07b776d68.json` | `evidence/etp-t4/VACUITY.json` | produced by the same superseded scan |
| `TRACEABILITY-superseded-t4-07b776d68.json` | `evidence/etp-t1/TRACEABILITY.json` | its ETP-T4 projection (inventory digest, scanner digest, source-tree digest and class counts) described the superseded scan; the graph identity `21bea318819a56f641b3aa2f25027216b97a1c4d` is unchanged |

The superseded source-tree digest is reproducible from the named commit:

```
git archive 07b776d688fdd1dcc4e315661894c30e623aed9e src | tar -x -C <dir>
```

Hashing every `*.rs` file under `<dir>/src` as `<relative-path> NUL
<sha256-of-text> LF` in sorted order yields
`b38e0f426c967da4e5433217b6e03b3042bf8773a0cea1dee0d778c637651a7d`, the
digest recorded in the superseded inventory.

The repair and its evidence are described in
`evidence/etp-controls/DRIFT-REPAIR.md`.
