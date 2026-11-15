# b80 measurement record (build/measurement subagent)

Source S: `d9fdf1357c7df26e36d15c1cda5154479b052c16` (branch `stage/p25/b75-ocsp`, tag `b80`).
Tracked tree clean at start; two untracked b79 evidence ledgers present
(`evidence/ssh-artifact-ledger-b79.json`, `evidence/sshd-artifact-ledger-b79.json`).
No commit or push was performed.

## Venue

Court recreated at the directed 16 GiB / 16 CPU venue:
`Memory=17179869184 MemoryReservation=17179869184 MemorySwap=17179869184 NanoCpus=16000000000 Pids=2048`,
`RLIMIT_DATA=12582912` KiB (`OPENSSL_RS_COURT_DATA`), `CARGO_BUILD_JOBS=8`.
Host `free -g` available before every heavy step: 33, 32, 31, 33, 33, 33 GiB (floor 24 GiB met).
One heavy command at a time. Peak container `memory.current` observed 9,204,944,896 B
(8.57 GiB of the 16 GiB cap) during the sshd closure. `oom=0 oom_kill=0` after every step.

| step | elapsed | peak bytes | exit |
|---|---|---|---|
| build_phase2.sh | 30 s | 2,084,352,000 | 0 |
| openssh client-b80 | 20 s | 392,441,856 | 0 |
| openssh server-b80 | 20 s | 461,238,272 | 0 |
| clippy census stream | 20 s | 5,029,261,312 | 0 |
| v1_census.py | 40 s | 1,764,974,592 | 0 |
| closure ssh | 2660 s | 7,990,034,432 | 0 |
| closure sshd | 2460 s | 9,204,944,896 | 0 |
| build-link measure openssh | 41 s | 4,659,359,744 | 0 |

## Install artefacts (all six changed vs b79; each size +1,712 B)

| file | sha256 | size | b79 |
|---|---|---|---|
| lib/libcrypto.so.3 | `60c1111250684556012dac7436c4aea3115b8697e7845c81c5ffb7fbf4c112f2` | 16887896 | 3045bd2d… CHANGED |
| lib/libssl.so.3 | `2eebf3f6c6f0a71d3f83fbbb63157b1083937e25db8085408e0c22b24da5592a` | 16600968 | 7136545e… CHANGED |
| lib/libcrypto.a | `947ea4fa62435d15e72723449f1b713f53d76cf9a8326f1a0769186f01f88962` | 44460996 | a296065d… CHANGED |
| lib/libssl.a | `51a0ff277c2418a441dcef60c34b3bae41e226eb94386a840331204812902eb0` | 44461546 | 7657f872… CHANGED |
| lib/ossl-modules/legacy.so | `74d319b8bd9f4521b973fb7f428ceb2f0d5e22e83d0142adbfaff00a35d2a625` | 16563880 | 81648818… CHANGED |
| bin/openssl | `6fed34b11d6354e936e65ea2b9ab20736a17818f5fb9c7e203ee83a15dd66fe0` | 12403496 | 73cf47e2… CHANGED |

Phase 2 courts: 11/11 pass, `all_pass=True` (`artifacts/phase2/COURTS.json`), authority
`openssl-3.6.4-production`; pkg-config resolves `openssl libssl libcrypto 3.6.4`.

## Consumers (unmodified portable OpenSSH 9.9p1)

Tarball check `b343fbcd…`: OK in both trees. `ssh -V`: `OpenSSH_9.9p1, OpenSSL 3.6.4 25 Aug 2026`.
ldd (ssh, sshd, ssh-keygen): `libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3`.

| artefact | sha256 | size |
|---|---|---|
| client-b80 ssh | `f8f454782e6a793a624687755a779ad4b6cb9bbb8693f35f2a1f5f9d16234607` | 3401744 |
| server-b80 sshd | `152ccc3465240454b5ec0cd470dfa81dc7eb044c01c9bbe72519a65a71919b92` | 1763248 |
| server-b80 sshd-session | `644bb0e0d0f911e92b63c59410be7c79207bf2e8b3bc607d80ff59e1e99b1941` | 3594840 |

## Census (`court/freeze-b80/census-b80.json`)

Identity `d9fdf1357…`, tracked clean, untracked = the two b79 ledgers; generated 2026-11-15T09:03:40Z.
Compiler input: `cargo clippy --lib --tests --message-format=json -- --cap-lints warn -W unsafe_code
-W clippy::undocumented_unsafe_blocks -W clippy::missing_safety_doc`.
Raw diagnostics 140977 (+8), unique sites 61632 (+6), files with unsafe block 787 (0).
By kind vs b79b: UNSAFE_BLOCK 47787 (+6); UNSAFE_FN_DEF 13491 (0); UNSAFE_IMPL 336 (0);
UNSAFE_EXTERN_BLOCK 9 (0); UNSAFE_TRAIT 9 (0).
Partition recomputed 99 ZERO_UNSAFE / 16 BOUNDARY_COVERED / 763 PARTIAL (identical);
recorded 92/18/761/6 (identical).
Delta vs b79b: production ops `cms_asn1.rs` 96→97, `v3_san.rs` 257→258; classification
`cms_lib.rs` all_operations_contracted False→True; no files added/removed.

## Closures

Tool `consumer_closure.py` v6 sha256 `6e9cd261c396b561d4f1a61b1de6879cb255e69eed9ec3188ea4f0196e0147a8`.

| | ssh | sshd |
|---|---|---|
| reachable files / functions | 626 / 8760 | 625 / 8727 |
| obligations | 290 D286 B4 U0 | 290 D286 B4 U0 |
| verdict | ACCEPTED (`safe_compatible:false`, "no refusal condition fired") | same |
| element 7 | **FAIL** (target_bounded 2, contract_bounded 151, unclassified 0) | **FAIL** (same) |
| carried_forward / removed / stale refusals | 278 / 3 / 2 | 278 / 3 / 2 |
| receipt | `dc296a34…` 13580282 B | `bc9f7be4…` 13426688 B |

Grouping `by_mechanism` (both): X509_VERIFY_POLICY 122, EVP_PKEY_PROVIDER 116,
RAND_CMS_STORE_KEYFMT 27, SSL_SESSION 14, C_ABI_CONTRACT 5, RUNTIME_CONCURRENCY 4, BIO 2.

### delta queue vs b79c: 4 newly BLOCKED (b79c had 0), no NEW obligation

1. `src/cms/cms_asn1.rs:617` → census 680 `UNSAFE_FN_DEF cms_ri_cb` —
   `content-addressed scoped discharge refused: boundary src/cms/cms_asn1.rs:671 names (src/cms/cms_asn1.rs, UNSAFE_FN_DEF, cms_ri_cb) but span-hash-mismatch: recorded span_sha256 f1f667a2ee29d165 does not match the current span fd94cb262e8ff33d.`
2. `src/x509/v3_san.rs:1069` → census 1077 `UNSAFE_FN_DEF v2i_GENERAL_NAME_ex` —
   `... boundary src/x509/v3_san.rs:1069 ... recorded span_sha256 095944c0642818b9 does not match the current span b01dcb8bfc373c3a.`
3. `src/cms/cms_lib.rs:1378` → census 1388 `UNSAFE_FN_DEF x509_free_void` —
   `stale scoped discharge refused: boundary CMS-FREE-001 declares [[1378, 1378]] ... current census coordinate 1388 (previously enumerated at 1378); the declared range does not cover the current coordinate, and a line range may only narrow a stable-identity match, never establish it; content-addressed check also refused: span-hash-mismatch.`
4. `src/cms/cms_lib.rs:1384` → census 1400 `UNSAFE_FN_DEF x509_crl_free_void` —
   same wording with `CMS-FREE-002 declares [[1384, 1384], [0, 0]]`, current coordinate 1400.

All four carry `mechanism_state=OWNERSHIP_RECONSTRUCTED`; all cite a documented contract but
"a contract transfers the obligation to the caller, it does not discharge it".

### element-7 FAIL cause

Two reachable unresolved sites are target-bounded only: `libcrypto.so.3` `CONF_free`
call site `0x2dd4c6` and `CONF_load` call site `0x2dd6eb`, both `call *0x10(%rax)`,
reason `base-slot-partial` (class `field`). b79c had 0 target-bounded sites; the same rebuild
also drops the three `ProvGcmHw.{aadupdate,cipherupdate,cipherfinal}` hw-table witness rows and
renames the AES-CTS witness (`CRYPTO_nistcts128_encrypt_block … (block)` → `…_encrypt … (cbc)` ×2).
No GCM/CTS/CONF source changed in this batch, so this is witness/layout sensitivity, not a
semantic change — but per §7/§21 it is a failing gate and must be re-witnessed, not waived.

## Build/link atlas row

`--measure --only openssh --reuse-committed --reuse-previous-candidate`, 41 s, exit 0.
openssh rows: authority + candidate both `L4-linked`, `outcome=reached`, `linkage_proven=true`,
`imported_openssl_symbols_count=179`, artifact `c8723f34…`, `source_root_hash 4a5abaf3…`,
`candidate_specific_patch_count=0`.
Durable row digest (canonical row minus `steps[].elapsed_seconds`) reproduces exactly:
authority `e2e0cc3b7bde754104fed3968d638ba31ffbfb84…`, candidate `d1a319afe8e09aeb5e943d902e93e25287950ad6…`.
Document `body_hash` changed b8b188a6… → d7eea72b… (timing-bearing, not an identity).
Atlas now names candidate install `60c11112…` / `2eebf3f6…`.

## Ordering caveat (must be resolved before freeze)

The closures were run before the atlas re-measure (task order), so both receipts carry
`ledger_record.artifact_matches_this_build=false` against the b79 row
(`recorded_candidate_install 3045bd2d…`). The closures themselves admitted the b80 install
digest for freshness, but the ledger binding is stale; rebind/re-run is needed for a coherent
b80 freeze.

## Working tree after measurement (not committed)

`M` install artefacts (8 files) + `forensics/atlas/implemented-surface.json` +
`forensics/downstream/build-link-atlas.json`; `?? evidence/closure-{ssh,sshd}-b80.json` and the
two b79 ledgers.
