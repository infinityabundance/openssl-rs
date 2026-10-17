# Safe-33 atlas refresh — candidate-bound ownership-reconstruction status

Generated 2026-10-17T15:26:08Z by `forensics/memory-safety/campaign/safe-c33/atlas_refresh.py` (stdlib only). **Measurement only** — no source conversion, no Phase-25 regeneration, no graduation claimed.

## Candidate pin

- HEAD `03d4e76b984f0654e80a2c589b877d3d5ea353c3` on `integrate/safe-c33`
- crate `openssl-rs 0.0.27`
- `src/**/*.rs`: **866** files, content sha256 `ad81d5351f24951843c72d0992166babd7f1f3cb61954d3e876f648a5deb029c`
- frozen inventory was at `67ae7f8e9f3381ce0dac1dae9a23bfa3937bec34` (base `b5bbb457ec6a3fd57ab5f9890d1bae3bbe7fe491`); this refresh re-pins the current tree

## The frozen 33 (authoritative: `state.json#cohort`)

- verdict `DROP_IN_PASS`, **33** families (8 L7-functional, 25 L4-linked)
- p1000 counts: `DROP_IN_PASS=33`, `DROP_IN_FAIL=0`, `DROP_IN_NOT_APPLICABLE=967`
- 33 names verified against `p1000-run.json`: True

| family | level | libssl | evidence |
|---|---|---|---|
| curl | L7-functional | true | fingerprint |
| cyrus-sasl | L4-linked | false | linkage-inferred |
| dovecot | L4-linked | true | linkage-inferred |
| fetchmail | L4-linked | true | linkage-inferred |
| fossil | L4-linked | true | linkage-inferred |
| haproxy | L7-functional | true | fingerprint |
| hiredis-ssl | L4-linked | true | linkage-inferred |
| iperf3 | L4-linked | false | linkage-inferred |
| isync | L7-functional | true | linkage-inferred |
| keepalived | L4-linked | true | linkage-inferred |
| kmod | L4-linked | false | linkage-inferred |
| ldns | L4-linked | false | linkage-inferred |
| libarchive | L4-linked | false | linkage-inferred |
| libevent | L4-linked | true | linkage-inferred |
| librdkafka | L4-linked | true | linkage-inferred |
| libretls | L4-linked | true | linkage-inferred |
| links | L4-linked | true | linkage-inferred |
| monit | L7-functional | true | fingerprint |
| mosquitto | L4-linked | true | linkage-inferred |
| nginx | L7-functional | true | linkage-inferred |
| openssh | L7-functional | false | fingerprint |
| openvpn | L4-linked | true | linkage-inferred |
| proxytunnel | L4-linked | true | linkage-inferred |
| pure-ftpd | L7-functional | true | fingerprint |
| redis | L7-functional | true | fingerprint |
| rsync | L4-linked | false | linkage-inferred |
| socat | L4-linked | true | linkage-inferred |
| squid | L4-linked | true | linkage-inferred |
| sslscan | L4-linked | true | linkage-inferred |
| ssmtp | L4-linked | true | linkage-inferred |
| stunnel | L4-linked | true | linkage-inferred |
| tinc | L4-linked | false | linkage-inferred |
| tnftp | L4-linked | true | linkage-inferred |

## Nine mechanisms — ownership-reconstruction status

`state` is from `state.json` (vocabulary: `UNSAFE_OPEN` < `OWNERSHIP_RECONSTRUCTED` < `SAFETY_DISCHARGED`; **none** is discharged). `closure` / `seam` / `no-seam+raw` are recomputed against the current tree.

| mechanism | state | families | closure files | seam files | no-seam+raw files | closure raw sites |
|---|---|---|---|---|---|---|
| ERR | UNSAFE_OPEN | 33 | 7 | 1 | 1 | 22 |
| RAND_CMS_STORE_KEYFMT | OWNERSHIP_RECONSTRUCTED | 33 | 83 | 45 | 2 | 430 |
| BIO | UNSAFE_OPEN | 32 | 34 | 21 | 0 | 134 |
| EVP_PKEY_PROVIDER | OWNERSHIP_RECONSTRUCTED | 32 | 270 | 154 | 7 | 1843 |
| RUNTIME_ALLOC_OWNERSHIP | UNSAFE_OPEN | 31 | 12 | 6 | 1 | 113 |
| ASN1_OCSP | UNSAFE_OPEN | 31 | 79 | 33 | 1 | 177 |
| X509_VERIFY_POLICY | OWNERSHIP_RECONSTRUCTED | 31 | 97 | 39 | 10 | 437 |
| RUNTIME_CONCURRENCY | OWNERSHIP_RECONSTRUCTED | 25 | 5 | 3 | 2 | 41 |
| SSL_SESSION | OWNERSHIP_RECONSTRUCTED | 25 | 44 | 13 | 4 | 303 |

## Cohort metrics (items 1–5, reported independently)

| # | metric | value |
|---|---|---|
| 1 | unique source files in the union of the nine closures | **628** |
| 2 | files with reconstructed ownership (seam present) | **313** |
| 3 | files with fully discharged obligations | **0** |
| 4 | unresolved interior raw-allocator sites in the closure | **3435** (upper bound; 143 unambiguous) |
| 5 | consumers eligible for `SAFE_COMPATIBLE` | **0** |

- **3** is 0 by construction: Obligations are discharged ONLY at the seal point (AGENTS.md §7 SAFETY_DISCHARGED, §18). No per-site validity contract has been proven for any closure file at this candidate, so this is honestly 0. A present seam is OWNERSHIP_RECONSTRUCTED, which is not discharge.
- **4** detail: Sites in no-seam files are unambiguously unconverted interior. Sites in seam-bearing files are mixed: they include legitimate seam-constructor sites and any remaining interior sites — this lightweight pass cannot separate them, so they are reported, not claimed clean.
- **4** exclusions: the `CRYPTO_*` allocator definitions (`src/runtime/mem.rs`) are the seam itself, not interior residuals, and are excluded from the count above.

### Whole-tree scan (current candidate)

- files with a seam: **374**
- files with zero raw allocator sites: **507**
- files with raw allocator sites remaining: **359**
- raw allocator sites total (incl. legitimate seam ctors): **4290**
- allocator-definition files (seam itself, excluded from metric 4): `src/runtime/mem.rs`

Seam tokens counted: `OwnedCtx`, `OwnedBuf`, `OwnedBlock`, `OwnedStr`, `PropqSlot`, `RawCtx`, `OwnedRaw`, `CtxDestroy`, `CipherDestroy`, `impl Drop`.

> Caveat — *seam present* is a **file-level heuristic**: a file is counted as reconstructed if any seam token appears anywhere, even for an unrelated inner type. It is an upper bound on reconstructed ownership, used for reachability, never a per-site proof.

### Mapping coverage (unknown coverage, stated)

src modules named by none of the nine mechanism directory rules (e.g. mac, sm2, modes, des, sm3). Their conversion work is real but is OUT of this nine-mechanism closure: a known coverage gap of this refresh, not a claim they are unconverted.

Top-level modules outside the nine-mechanism closure (files): `apps`(59), `runtime`(30), `engine`(20), `digest`(14), `slh_dsa`(12), `ml_dsa`(11), `ct`(10), `modes`(7), `compat`(6), `mac`(6), `ml_kem`(5), `ui`(5), `async`(4), `ess`(3), `http`(3), `sm2`(3), `srp`(3), `dso`(2).

## Per-consumer mechanism status (metric 5)

`recon` = mechanisms the consumer needs that are `OWNERSHIP_RECONSTRUCTED`; `open` = `UNSAFE_OPEN`. Eligible = needs **all** its mechanisms discharged.

| family | level | mechs | recon | open | open mechanisms | eligible |
|---|---|---|---|---|---|---|
| curl | L7-functional | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| cyrus-sasl | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| dovecot | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| fetchmail | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| fossil | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| haproxy | L7-functional | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| hiredis-ssl | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| iperf3 | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| isync | L7-functional | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| keepalived | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| kmod | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| ldns | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| libarchive | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| libevent | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| librdkafka | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| libretls | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| links | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| monit | L7-functional | 7 | 4 | 3 | ASN1_OCSP, BIO, ERR | no |
| mosquitto | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| nginx | L7-functional | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| openssh | L7-functional | 8 | 4 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| openvpn | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| proxytunnel | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| pure-ftpd | L7-functional | 4 | 3 | 1 | ERR | no |
| redis | L7-functional | 7 | 4 | 3 | BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| rsync | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| socat | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| squid | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| sslscan | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| ssmtp | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| stunnel | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| tinc | L4-linked | 7 | 3 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |
| tnftp | L4-linked | 9 | 5 | 4 | ASN1_OCSP, BIO, ERR, RUNTIME_ALLOC_OWNERSHIP | no |

## Distinguishing unknown coverage from demonstrated failure

- **Unknown coverage** — Mechanism dependence is MEASURED (symbol fingerprint) for 6 families and INFERRED (linkage/surface) for 27; isync and nginx reach L7 with no fingerprint. The join speaks for 6 of 1000. Absence of a fingerprint is unknown coverage, not a pass.
  - mechanisms with linkage-inferred families: ERR (27), RAND_CMS_STORE_KEYFMT (27), BIO (27), EVP_PKEY_PROVIDER (27), RUNTIME_ALLOC_OWNERSHIP (27), ASN1_OCSP (27), X509_VERIFY_POLICY (27), RUNTIME_CONCURRENCY (20), SSL_SESSION (20)
- **Demonstrated failure** — A closure file with a raw allocator site and NO ownership seam is a known-unconverted interior site in a mechanism a consumer needs. This is the only class this refresh asserts as failure-shaped; it is not a functional regression.
  - mechanisms with unconverted (no-seam) interior files: ERR (1), RAND_CMS_STORE_KEYFMT (2), EVP_PKEY_PROVIDER (7), RUNTIME_ALLOC_OWNERSHIP (1), ASN1_OCSP (1), X509_VERIFY_POLICY (10), RUNTIME_CONCURRENCY (2), SSL_SESSION (4)

## Next engineering target (reachability × residual risk)

`score = families reaching the mechanism × unconverted no-seam interior sites`. Reachability is the count of the 33 that depend on the mechanism (upper bound); residual risk is the unambiguous no-seam interior sites.

| rank | mechanism | state | families reaching | no-seam interior files | no-seam interior sites | score |
|---|---|---|---|---|---|---|
| 1 | EVP_PKEY_PROVIDER | OWNERSHIP_RECONSTRUCTED | 32 | 7 | 42 | 1344 |
| 2 | SSL_SESSION | OWNERSHIP_RECONSTRUCTED | 25 | 4 | 25 | 625 |
| 3 | RUNTIME_ALLOC_OWNERSHIP | UNSAFE_OPEN | 31 | 1 | 20 | 620 |
| 4 | X509_VERIFY_POLICY | OWNERSHIP_RECONSTRUCTED | 31 | 10 | 17 | 527 |
| 5 | RUNTIME_CONCURRENCY | OWNERSHIP_RECONSTRUCTED | 25 | 2 | 21 | 525 |
| 6 | RAND_CMS_STORE_KEYFMT | OWNERSHIP_RECONSTRUCTED | 33 | 2 | 7 | 231 |
| 7 | ASN1_OCSP | UNSAFE_OPEN | 31 | 1 | 7 | 217 |
| 8 | ERR | UNSAFE_OPEN | 33 | 1 | 4 | 132 |
| 9 | BIO | UNSAFE_OPEN | 32 | 0 | 0 | 0 |

## Candidate-binding cross-check vs the frozen census

- closure files matching frozen census hash: 277
- closure files CHANGED since the frozen census: 348
- closure files absent from the frozen census: 3
- The census is the FROZEN Phase-25 atlas (earlier candidate). A changed file is candidate drift since that freeze, not a defect.

## Ledger vs seam heuristic

Of **26** files the ledger lists as converted on this branch, **5** carry no recognised seam token: `src/evp/p_legacy.rs`, `src/x509/pcy_data.rs`, `src/x509/pcy_lib.rs`, `src/context/namemap.rs`, `src/runtime/thread_events.rs`.

Files state.json lists as converted_files_on_branch that carry NO recognised seam token in the current tree. The file-level seam heuristic therefore UNDERCOUNTS reconstruction for structural/lock-based conversions that leave no owner token.

## Non-claims

- This refresh measures ownership-reconstruction progress only; it claims no SAFETY_DISCHARGED and no SAFE_COMPATIBLE.
- The 33 historical DROP_IN_PASS verdicts are against an EARLIER candidate; functional re-testing is required before graduation.
- A present seam (OwnedCtx/OwnedBuf/impl Drop/…) is OWNERSHIP_RECONSTRUCTED, never discharge.
- Mechanism→file association is a declared directory mapping, not a per-symbol proof; it is an upper bound used for reachability.
- Raw allocator sites in seam-bearing files are reported, not claimed converted.
