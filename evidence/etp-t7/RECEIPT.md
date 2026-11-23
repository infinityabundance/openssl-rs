# ETP-T7 receipt — side-channel and erasure verification

**Item:** `docs/ETP-TODO.md` ETP-T7.
**Candidate:** `0eddfe839f552a6e22a8cf375ec308c8bf7c478b` on `staging`.
**Worktree:** clean at the start (`git status --porcelain` empty); the files listed
at the end are this item's deliverables and are not committed here.
**Verdict:** classification `REGISTERED`; erasure gaps `RECORDED_NOT_REPAIRED`;
instrument controls `PASS` at the registered geometry; **no constant-time claim**.

---

## 1. Venue and memory discipline

`free -g` was read before every heavy command:

| before | `available` (GiB) |
|---|---:|
| court probe | 28 |
| dudect build and run | 27 |
| validator and checker run | 25 |
| final gate (document edit done) | 25 |

All commands ran in the court:

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec sh -c '<command>'
```

Venue observed: `cc (Debian 12.2.0-14+deb12u1) 12.2.0`, Python 3.11.2,
`nproc` 30, work directory `/work`. The host `available` reading was at or above
the 24 GiB line in `AGENTS.md` §6.1 for every build.

## 2. The measurement

The prospective preregistration is
`evidence/etp-t7/PREREGISTRATION.json`, SHA-256
`d28964cc44411a43327afd8cc80d34d13eb936bc9fab523f21dbb3d3cba3120e`. It was
written before the run. The receipt quotes that digest.

Build:

```
cc -O2 -g -D_GNU_SOURCE \
  -I courts/phase18/timing/third_party/dudect \
  -I artifacts/phase2/install/include \
  courts/phase18/timing/dudect_bn.c \
  -L artifacts/phase2/install/lib -lcrypto -lm \
  -Wl,-rpath,/work/artifacts/phase2/install/lib -o /tmp/dudect_etp7
```

Identities:

| item | digest |
|---|---|
| harness binary `/tmp/dudect_etp7` | `627882a8991350897dceb492daf4d634534f48e4a8269db7499ef89836f242e7` |
| harness source `courts/phase18/timing/dudect_bn.c` | `bd898fd22b998b6b9e22a64d2bdd5ee42a5d9d7dc4a08a9df6a9e2ba01dd5a7b` |
| header `courts/phase18/timing/third_party/dudect/dudect.h` | `3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da` |
| loaded DSO `libcrypto.so.3` | `fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9` |

`ldd /tmp/dudect_etp7` resolved `libcrypto.so.3` to
`/work/artifacts/phase2/install/lib/libcrypto.so.3`, and the on-disk digest is
the one above. The DSO's source identity is `UNKNOWN`; no source-to-binary
correspondence is claimed.

Executed, one process per mode, pinned with `taskset -c 1`:

```
LD_LIBRARY_PATH=/work/artifacts/phase2/install/lib \
  taskset -c 1 /tmp/dudect_etp7 cmpcmp 10000
LD_LIBRARY_PATH=/work/artifacts/phase2/install/lib \
  taskset -c 1 /tmp/dudect_etp7 cmpnaive 10000
```

| mode | role | total measurements | batches | state | exit | max abs t |
|---|---|---:|---:|---:|---:|---:|
| `cmpcmp` | negative control | 30 000 | 3 | 1 (`DUDECT_NO_LEAKAGE_EVIDENCE_YET`) | 1 | 0.98 |
| `cmpnaive` | positive control | 30 000 | 3 | 0 (`DUDECT_LEAKAGE_FOUND`) | 0 | 208.01 |

Transcripts: `evidence/etp-t7/logs/dudect-cmpcmp.{out,err}` and
`evidence/etp-t7/logs/dudect-cmpnaive.{out,err}`. Digests are in
`evidence/etp-t7/DUDECT-ETP-T7.json`.

**Deviation.** The preregistered stopping condition said to stop a mode at
state 0. The pinned harness runs the full batch budget and reports the state
afterwards, so `cmpnaive` ran three batches. No measurement was added, removed
or replaced; the realised geometry is inside the registered budget and matches
`per_batch` and `max_batches`. The preregistration was not amended after the run.

## 3. Preregistration match

Two instances are recorded.

- `ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1` (`PROSPECTIVE`) matches
  `evidence/etp-t7/DUDECT-ETP-T7.json`:
  `PREREG_CHECK ok instance=ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1`.
- `ETP-T7-DUDECT-LEGACY-RECONSTRUCTED` (`RECONSTRUCTED_POST_HOC`) matches the
  receipt already in the tree,
  `courts/phase18/timing/RECEIPT-dudect-modes.json`:
  `PREREG_CHECK ok instance=ETP-T7-DUDECT-LEGACY-RECONSTRUCTED`. The legacy
  adapter reads `ops` where present and the recorded `dudect.executed` transcript
  where it is not, checking the transcript digest first.

The reconstructed instance is not evidence of prospective registration. It
records that the seven recorded modes ran at 20 000 per batch within a
three-batch budget, and it supports no constant-time claim.

## 4. Classification counts

`python3 forensics/tools/side_channel_erasure.py validate` printed:

```
entries 51
PUBLIC_DATA 3
SECRET_DATA 29
SECRET_DEPENDENT_CONTROL 9
CLEANSING_REQUIRED 5
DECLASSIFICATION_BOUNDARY 5
```

`SECRET_DEPENDENT_CONTROL` entries with evidence `NONE`:

```
AES-SBOX  SM4-SBOX  ARIA-SBOX  CAMELLIA-SBOX  LIMB-NORMALISE  PKEY-XLAT-BUFLEN
```

The remaining three (`STORE-CONSTTIME`, `ECDSA-NONCE-LOOP`, `ECDSA-RETRY-LOOP`)
have ctgrind evidence that reports a finding; the counts are quoted from
`courts/phase18/timing/RECEIPT-timing-unified.json`.

## 5. Erasure findings

Fifteen cleansing release arms were checked as present. One authority
`OPENSSL_clear_free` arm did not survive conversion. Seven gaps were recorded and
none was repaired:

| id | class | severity | source | named repair |
|---|---|---|---|---|
| `ERA-01` | `FREED_WITHOUT_CLEANSING` | HIGH | `src/ssl/ssl_lib.rs:3728` | cleanse the inline TLS schedules before the connection block release |
| `ERA-02` | `LOST_CLEAR_FREE_ARM` | MEDIUM | `src/apps/mac.rs:262` | restore the cleansing release for the `BUFSIZE` scratch |
| `ERA-03` | `FREED_WITHOUT_CLEANSING` | MEDIUM | `src/asn1/x_pkey.rs:105` | cleanse `key_data` over its recorded extent |
| `ERA-04` | `FAILURE_PATH_WITHOUT_CLEANSING` | MEDIUM | `src/evp/pkey_ctx.rs:4559` | cleanse `buflen` on the `BN_bn2nativepad` failure path |
| `ERA-05` | `FREED_WITHOUT_CLEANSING` | MEDIUM | `src/evp/pkey_ctx.rs:3597` | cleanse `buflen` before the cleanup release |
| `ERA-06` | `FREED_WITHOUT_CLEANSING` | MEDIUM | `src/bn/blinding.rs:301` | release the blinding factors with `BN_clear_free` |
| `ERA-07` | `LENGTH_ONLY_CLEANSE` | LOW | `src/asn1/string.rs:332` | cleanse the allocation extent, not only the current length |

The audit summary recomputed by the validator:

```
findings 7
FREED_WITHOUT_CLEANSING 4
LENGTH_ONLY_CLEANSE 1
FAILURE_PATH_WITHOUT_CLEANSING 1
LOST_CLEAR_FREE_ARM 1
HIGH 1  MEDIUM 5  LOW 1
clear_free_arms_checked 15
clear_free_arms_lost 1
repaired 0
```

## 6. Refusal controls

`forensics/tools/side_channel_erasure.py --self-test` printed `SELF-TEST PASS
failures=0`. The observed refusals, one per rule:

| rule | control | observed |
|---|---|---|
| 1 | `NC-1` | `CT_T_WITHOUT_PREREGISTERED_GEOMETRY` |
| 2 | `NC-2` | `CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT` |
| 3 | `NC-3` | `DEBUG_BINARY_GENERALISED_TO_RELEASE` |
| 4 | `NC-4` (`AES-SBOX`) | `SECRET_DEPENDENT_CONTROL_WITHOUT_EVIDENCE` |
| 5 | `NC-5` | `EXCLUSIONS_CHANGED_AFTER_RUN` |
| 6 | `NC-6` | `DUDECT_STATE_1_TREATED_AS_PROOF` |

The positive controls `PC-1`…`PC-6` were accepted. Mutation controls for the
register and audit were refused by `SE_COUNT_MISMATCH`, `SE_SOURCE_TOKEN`,
`ER_UNKNOWN_SECRET_REF`, `ER_UNCOVERED_OBLIGATION`, `ER_BAD_SCHEMA` and
`PR_BAD_GEOMETRY`.

`forensics/tools/preregistration_check.py --self-test` printed `SELF-TEST PASS
failures=0`, covering the two committed receipts and ten mutations: changed
preregistration digest, changed artefact digest, changed harness source, missing
harness binary, batch budget exceeded, batch count inconsistent with the total,
quiet positive control, firing negative control, missing declared mode,
undeclared mode, and a changed reconstructed positive control.

## 7. Gate output

```
JSON_OK evidence/etp-t7/SECRETS.json
JSON_OK evidence/etp-t7/PREREGISTRATION.json
JSON_OK evidence/etp-t7/ERASURE-AUDIT.json
JSON_OK evidence/etp-t7/DUDECT-ETP-T7.json
side_channel_erasure.py validate  -> {"ok": true, ...}
side_channel_erasure.py --self-test -> SELF-TEST PASS failures=0
preregistration_check.py (prospective) -> PREREG_CHECK ok
preregistration_check.py (reconstructed) -> PREREG_CHECK ok
preregistration_check.py --self-test -> SELF-TEST PASS failures=0
tests/test_side_channel_erasure.py -> Ran 23 tests ... OK
```

No Rust source was changed, so no crate build or library test run is part of
this item.

## 8. Files and digests

| file | SHA-256 |
|---|---|
| `evidence/etp-t7/SECRETS.json` | `b6f30fa86e2767efc9eb861faedbf099749a4b1288c7d2705ed2f29e01cf67a1` |
| `evidence/etp-t7/PREREGISTRATION.json` | `d28964cc44411a43327afd8cc80d34d13eb936bc9fab523f21dbb3d3cba3120e` |
| `evidence/etp-t7/DUDECT-ETP-T7.json` | `6f8ab3956e01947bc524bdc3ebfb764ea8269a0fb82cc9736eba6776b5c8b9b7` |
| `evidence/etp-t7/ERASURE-AUDIT.json` | `99c7fa1acdd8f6e1f78c4fd16302f0ff431be7feb951cbca2c5b91f9239d2117` |
| `forensics/tools/side_channel_erasure.py` | `9476b386d268be0597bc47701aca8c058094bc05dd6ac9695898a81ddd3b8aad` |
| `forensics/tools/preregistration_check.py` | `39933bbfb8a2de6d602a395a12b8094da6338a6b0ecacd1c9e4b7ead7f78dee9` |
| `forensics/tools/tests/test_side_channel_erasure.py` | `d67bc00f9eb287e620340d9dbaedb8bf19d08700537a59233c129a0967a82e6d` |
| `docs/SIDE-CHANNEL-AND-ERASURE.md` | `4474aa349823a09987a78b3bf4c220316f3f317433dd7eef2589f8591af037cd` |
| `evidence/etp-t7/logs/dudect-cmpcmp.err` | `354994cb34d022db8d59c698e06504463b544b56e2a5ff08aa1b69113bb69df7` |
| `evidence/etp-t7/logs/dudect-cmpcmp.out` | `bb7f1d5ee1fc40129d24a98052bca39be4857a395a62bff8e765c76684e48c54` |
| `evidence/etp-t7/logs/dudect-cmpnaive.err` | `c78d25f09e74691b6a07a1c28f3d142c61b381314d3ec9f27ca4243650ccad8b` |
| `evidence/etp-t7/logs/dudect-cmpnaive.out` | `c9b7e7610106203f2cd380b0a9d90f905e89c63ff6e7ae811e19ff6013757cfe` |

## 9. Non-claims

- `cmpcmp` state 1 is absence of evidence at 10 000 × 3, not proof of
  constant-time behaviour.
- The run measures two comparison controls, not AES, BN, ECDSA, RSA, TLS or any
  erasure property.
- The DSO digest binds an on-disk artefact; it is not a source-to-binary
  correspondence and its source identity is `UNKNOWN`.
- The classification is not a census, and a source contract is not runtime
  evidence.
- The seven erasure gaps are recorded, not repaired, and no erasure obligation is
  promoted to discharged.
- The result does not generalise to another CPU, target, build profile or
  container.
