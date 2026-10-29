# Safe-33 atlas refresh — candidate-bound ownership-reconstruction status

> **Superseded by `STATUS-2026-10-20.md` (current counts).** This is a frozen
> 2026-10-17 receipt pinned to 0.0.27 and the then-current 8 L7 / 25 L4 split.
> The current atlas records 33/33 cohort families at `L7-functional`, six
> mechanisms are `SAFETY_DISCHARGED`, 0.0.42 is the published release and 0.0.43
> is the unpublished candidate. `SAFE_COMPATIBLE` is **0/33** because the
> closure's reachable bound is not monotone
> (`atlas-refresh/closure-monotonicity-finding.json`, **OPEN BLOCKING**): no
> obligation count from any candidate is carriable. The figures below remain true
> of the frozen candidate they cite.

Candidate stamp 2026-10-17T20:31:17Z (deterministic HEAD commit time; `SOURCE_DATE_EPOCH` honoured) by `{doc['generator']}` (stdlib only). **Measurement only** — no source conversion, no Phase-25 regeneration, no graduation claimed.

## Candidate pin

- HEAD `8751ea75f742c90c19b92564257566f71d606dcd` on `integrate/safe-c33`
- crate `openssl-rs 0.0.27`
- `src/**/*.rs`: **868** files, content sha256 `c06aea132e05ccb47651b3a668927db713e1391b53e50d1c7de9b4f1574ec653`
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

`state` is from `state.json` (vocabulary: `UNSAFE_OPEN` < `OWNERSHIP_RECONSTRUCTED` < `SAFETY_DISCHARGED`; **none** is discharged). `closure` / `seam` / call counts are recomputed against the current tree. **Production allocation calls** is a work-burden metric, not a defect count; test-only and allocator-seam calls are excluded.

| mechanism | state | families | closure files | seam files | no-seam prod-alloc files | production alloc calls | production release calls |
|---|---|---|---|---|---|---|---|
| ERR | UNSAFE_OPEN | 33 | 7 | 1 | 0 | 1 | 1 |
| RAND_CMS_STORE_KEYFMT | OWNERSHIP_RECONSTRUCTED | 33 | 83 | 45 | 2 | 36 | 41 |
| BIO | UNSAFE_OPEN | 32 | 34 | 21 | 0 | 26 | 34 |
| EVP_PKEY_PROVIDER | OWNERSHIP_RECONSTRUCTED | 32 | 270 | 154 | 3 | 312 | 337 |
| RUNTIME_ALLOC_OWNERSHIP | UNSAFE_OPEN | 31 | 12 | 6 | 1 | 8 | 12 |
| ASN1_OCSP | UNSAFE_OPEN | 31 | 79 | 33 | 0 | 23 | 18 |
| X509_VERIFY_POLICY | OWNERSHIP_RECONSTRUCTED | 31 | 97 | 39 | 7 | 67 | 54 |
| RUNTIME_CONCURRENCY | OWNERSHIP_RECONSTRUCTED | 25 | 5 | 4 | 1 | 7 | 15 |
| SSL_SESSION | OWNERSHIP_RECONSTRUCTED | 25 | 44 | 13 | 1 | 58 | 23 |

## Cohort metrics (items 1–5, reported independently)

| # | metric | value |
|---|---|---|
| 1 | unique source files in the union of the nine closures | **628** |
| 2 | files with reconstructed ownership (seam present) | **314** |
| 3 | files with fully discharged obligations | **0** |
| 4 | unresolved interior production calls in the closure (no-seam files) | **alloc: 21 calls / 15 files**; **release: 29 calls** |
| 5 | consumers eligible for `SAFE_COMPATIBLE` | **0** |

- **3** is 0 by construction: Obligations are discharged ONLY at the seal point (AGENTS.md §7 SAFETY_DISCHARGED, §18). No per-site validity contract has been proven for any closure file at this candidate, so this is honestly 0. A present seam is OWNERSHIP_RECONSTRUCTED, which is not discharge.
- **4** detail: Allocation calls and release calls are reported separately and must not be added into one 'raw site' figure. Calls in no-seam files are unambiguously unclassified interior work. Calls in seam-bearing files are mixed: they include legitimate seam-constructor/release sites and any remaining interior sites — this lightweight pass cannot separate them, so they are reported as classification burden, not as defects.
- **4** classification burden (not defects): 516 production allocation calls and 455 production release calls live in 177 seam-bearing closure files.
- **4** exclusions: the `CRYPTO_*` allocator definitions (`src/runtime/mem.rs`) are the seam itself, not interior residuals, and are excluded from the count above.

### Whole-tree call-site scan (current candidate)

A *site* is a call expression (`NAME(`), not a `use` import, comment mention or function-pointer table entry. Comments and string/char literals are stripped in place before scanning.

| class | calls | files |
|---|---|---|
| production allocation calls | **700** | 240 |
| production release calls | **657** | 212 |
| test-only calls (alloc + release; excludes the allocator-seam file) | 123 (alloc 62, release 61) | 30 |
| allocator-seam calls (all calls in `src/runtime/mem.rs`, `src/runtime/secure.rs`; including their own test modules; excluded above) | 71 (alloc 37, release 34, adoption 0) | 2 |

- files with a seam: **377**
- files with at least one production allocation call: **240**
- files with zero production allocation calls (excluding the seam file): **626**
- **files with at least one production allocation call and no recognised seam (the true no-seam candidate set): 18**
  - `src/bn/bignum.rs`, `src/cmp/cmp_util.rs`, `src/context/namemap.rs`, `src/ct/ct_x509v3.rs`, `src/evp/p_legacy.rs`, `src/ml_dsa/poly.rs`, `src/pkcs12/p12_mutl.rs`, `src/provider/activate.rs`, `src/runtime/thread_events.rs`, `src/sm2/crypt.rs`, `src/ssl/s3_lib.rs`, `src/x509/v3_enum.rs`, `src/x509/v3_group_ac.rs`, `src/x509/v3_ind_iss.rs`, `src/x509/v3_no_ass.rs`, `src/x509/v3_no_rev_avail.rs`, `src/x509/v3_single_use.rs`, `src/x509/v3_soa_id.rs`
- **sites inside seam-bearing files (classification burden, not defects): 670** production allocation calls in 222 files
- adoption/transfer calls recorded separately (never counted as raw sites): 294 total, 283 production
- allocator-seam files (excluded from consumer counts): `src/runtime/mem.rs`, `src/runtime/secure.rs`
- test-classification detail: cfg-attribute brace span for inline cfg(test) modules, path resolution for external `#[cfg(test)] mod name;` files, and brace/statement spans for individual cfg(test) items; not a full parser (residual limitation reported); 316 inline `cfg(test)` module spans, 11 individual cfg(test) item spans, 7 external `#[cfg(test)] mod name;` files treated as test-only (`src/ml_dsa/tests.rs`, `src/ml_kem/tests.rs`, `src/runtime/miri_tcb.rs`, `src/runtime/sparse_array_probe.rs`, `src/slh_dsa/tests.rs`, `src/ssl/adv_alloc.rs`, `src/test_support.rs`)
- sites reclassified test-only by individual-item cfg(test) ranges (not already covered by a module/file): **0** (alloc/release: 0)
- `cfg_attr(..., cfg(test))` attributes detected but NOT reclassified (conditional attribute, not a test-only marker): 0

Seam tokens counted: `OwnedCtx`, `OwnedBuf`, `OwnedBlock`, `OwnedStr`, `PropqSlot`, `RawCtx`, `OwnedRaw`, `CtxDestroy`, `CipherDestroy`, `impl Drop`.

### Discovered allocator surface

Derived from `src/runtime/mem.rs`, `src/runtime/secure.rs`: 18 allocation and 6 release call names.

- alloc: `CRYPTO_aligned_alloc`, `CRYPTO_aligned_alloc_array`, `CRYPTO_calloc`, `CRYPTO_clear_realloc`, `CRYPTO_clear_realloc_array`, `CRYPTO_malloc`, `CRYPTO_malloc_array`, `CRYPTO_memdup`, `CRYPTO_realloc`, `CRYPTO_realloc_array`, `CRYPTO_secure_calloc`, `CRYPTO_secure_malloc`, `CRYPTO_secure_malloc_array`, `CRYPTO_secure_malloc_init`, `CRYPTO_secure_zalloc`, `CRYPTO_strdup`, `CRYPTO_strndup`, `CRYPTO_zalloc`
- release: `CRYPTO_clear_free`, `CRYPTO_free`, `CRYPTO_secure_clear_free`, `CRYPTO_secure_free`, `CRYPTO_secure_malloc_done`, `OPENSSL_clear_free`
- `OPENSSL_*` aliases found as definitions: `OPENSSL_clear_free`
- public seam functions excluded as queries/utilities: `CRYPTO_get_mem_functions`, `CRYPTO_memcmp`, `CRYPTO_secure_actual_size`, `CRYPTO_secure_allocated`, `CRYPTO_secure_malloc_initialized`, `CRYPTO_secure_used`, `CRYPTO_set_mem_functions`, `OPENSSL_cleanse`

### Per-family production call counts

Family counts are kept separate so secure/cleansing/array/aligned/duplicate operations are visible and are not folded into a plain malloc figure. All counts are call sites; they are not defect counts.

| family | production alloc calls | files | production release calls | files | test-only calls | seam calls |
|---|---:|---:|---:|---:|---:|---:|
| aligned | 0 | 0 | 0 | 0 | 0 | 2 |
| array | 21 | 11 | 0 | 0 | 0 | 1 |
| calloc | 18 | 12 | 0 | 0 | 3 | 1 |
| cleansing_release | 0 | 0 | 122 | 39 | 1 | 1 |
| clear_realloc | 5 | 5 | 0 | 0 | 2 | 2 |
| dup | 289 | 122 | 0 | 0 | 13 | 0 |
| malloc | 160 | 88 | 0 | 0 | 31 | 8 |
| openssl_alias | 0 | 0 | 13 | 7 | 0 | 0 |
| plain_release | 0 | 0 | 491 | 192 | 56 | 7 |
| realloc | 11 | 10 | 0 | 0 | 4 | 0 |
| secure_alloc | 13 | 10 | 0 | 0 | 0 | 5 |
| secure_arena | 0 | 0 | 0 | 0 | 6 | 26 |
| secure_array | 1 | 1 | 0 | 0 | 0 | 3 |
| secure_calloc | 1 | 1 | 0 | 0 | 0 | 3 |
| secure_cleansing_release | 0 | 0 | 27 | 17 | 0 | 3 |
| secure_release | 0 | 0 | 4 | 4 | 0 | 5 |
| secure_zalloc | 7 | 5 | 0 | 0 | 0 | 2 |
| zalloc | 174 | 121 | 0 | 0 | 7 | 2 |

### Per-site worklist

Every production (non-test, non-seam) allocation and release call is written to `forensics/memory-safety/campaign/safe-c33/atlas-refresh/site-worklist.json` (**1357 rows**, sorted by file then line). Fields: `file`, `line`, `kind`, `callee`, `family`, `function`, `seam_bearing_file`, `in_safe33_closure`.

> Caveat — *seam present* is a **file-level heuristic** over the comment/literal-stripped source: a file is counted as reconstructed if any seam token appears anywhere in code, even for an unrelated inner type. It is an upper bound on reconstructed ownership, used for reachability, never a per-site proof.

### Mapping coverage (unknown coverage, stated)

src modules named by none of the nine mechanism directory rules (e.g. mac, sm2, modes, des, sm3). Their conversion work is real but is OUT of this nine-mechanism closure: a known coverage gap of this refresh, not a claim they are unconverted.

Top-level modules outside the nine-mechanism closure (files): `apps`(59), `runtime`(32), `engine`(20), `digest`(14), `slh_dsa`(12), `ml_dsa`(11), `ct`(10), `modes`(7), `compat`(6), `mac`(6), `ml_kem`(5), `ui`(5), `async`(4), `ess`(3), `http`(3), `sm2`(3), `srp`(3), `dso`(2).

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
- **Demonstrated failure** — A closure file with at least one production allocation CALL and NO ownership seam is a known-unconverted interior allocation site in a mechanism a consumer needs. This is the only class this refresh asserts as failure-shaped; it is not a functional regression.
  - mechanisms with unconverted (no-seam) interior files: RAND_CMS_STORE_KEYFMT (2), EVP_PKEY_PROVIDER (3), RUNTIME_ALLOC_OWNERSHIP (1), X509_VERIFY_POLICY (7), RUNTIME_CONCURRENCY (1), SSL_SESSION (1)

## Next engineering target (ranked by production allocation calls)

The rank metric is the corrected **production allocation call count** in the mechanism closure. It is a work-burden metric, **not a defect count**. Reachability is the count of the 33 that depend on the mechanism (upper bound) and is retained as context and in the secondary score. This ranking differs from the earlier report, which ranked by a conflated alloc+release figure over no-seam files only.

| rank | mechanism | state | production alloc calls | production release calls | families reaching | no-seam prod-alloc files | reach × alloc score |
|---|---|---|---|---|---|---|---|
| 1 | EVP_PKEY_PROVIDER | OWNERSHIP_RECONSTRUCTED | **312** | 337 | 32 | 3 | 9984 |
| 2 | X509_VERIFY_POLICY | OWNERSHIP_RECONSTRUCTED | **67** | 54 | 31 | 7 | 2077 |
| 3 | SSL_SESSION | OWNERSHIP_RECONSTRUCTED | **58** | 23 | 25 | 1 | 1450 |
| 4 | RAND_CMS_STORE_KEYFMT | OWNERSHIP_RECONSTRUCTED | **36** | 41 | 33 | 2 | 1188 |
| 5 | BIO | UNSAFE_OPEN | **26** | 34 | 32 | 0 | 832 |
| 6 | ASN1_OCSP | UNSAFE_OPEN | **23** | 18 | 31 | 0 | 713 |
| 7 | RUNTIME_ALLOC_OWNERSHIP | UNSAFE_OPEN | **8** | 12 | 31 | 1 | 248 |
| 8 | RUNTIME_CONCURRENCY | OWNERSHIP_RECONSTRUCTED | **7** | 15 | 25 | 1 | 175 |
| 9 | ERR | UNSAFE_OPEN | **1** | 1 | 33 | 0 | 33 |

## Candidate-binding cross-check vs the frozen census

- closure files matching frozen census hash: 277
- closure files CHANGED since the frozen census: 348
- closure files absent from the frozen census: 3
- The census is the FROZEN Phase-25 atlas (earlier candidate). A changed file is candidate drift since that freeze, not a defect.

## Ledger vs seam heuristic

Of **26** files the ledger lists as converted on this branch, **5** carry no recognised seam token: `src/evp/p_legacy.rs`, `src/x509/pcy_data.rs`, `src/x509/pcy_lib.rs`, `src/context/namemap.rs`, `src/runtime/thread_events.rs`.

Files state.json lists as converted_files_on_branch that carry NO recognised seam token in the current tree. The file-level seam heuristic therefore UNDERCOUNTS reconstruction for structural/lock-based conversions that leave no owner token.

## Residual limitations (not papered over)

- The scanner is a hand-written lexical pass, not a Rust parser. It correctly ignores comments and string/char literals, but calls produced by macros or `include!` are not visible to it.
- Inline `#[cfg(test)] mod tests { … }` and external `#[cfg(test)] mod name;` files are reclassified as test-only, and `#[cfg(test)]`/`#[cfg(all(test, ...))]` on individual `fn`, `impl`, `const`, `use`, and `static` items is now reclassified by item span. `cfg(any(test, ...))` is deliberately treated as production (it can be enabled without `test`). `cfg_attr(..., cfg(test))` is detected and counted but NOT reclassified: a conditional attribute does not by itself make an item test-only. `cfg(test)` on struct fields or other non-item positions is not handled.
- External-module resolution covers `dir/mod.rs`, `src/lib.rs`/`main.rs`, and `dir/file.rs`; `#[path]` overrides and modules declared inside inline modules are not resolved.
- The allocator surface is derived from public `fn` definitions in `src/runtime/mem.rs` and `src/runtime/secure.rs`, plus `OPENSSL_*` alias definitions discovered elsewhere in `src/`. C macros (`OPENSSL_free`, `OPENSSL_malloc`, …) have no Rust function to discover; allocator wrappers defined outside the seam files are only counted if they are the declared seam names or an `OPENSSL_*` alias. `CRYPTO_secure_malloc_init`/`_done` are counted in the separate `secure_arena` family.
- Container/lock/ex_data operations that contain `alloc`/`free` are not heap block allocation or release and are deliberately excluded: `OPENSSL_sk_free`, `OPENSSL_sk_pop_free`, `OPENSSL_LH_free`, `OPENSSL_INIT_free`, `CRYPTO_THREAD_lock_free`, `CRYPTO_free_ex_data`, `CRYPTO_free_ex_index`, `CRYPTO_alloc_ex_data`, and `CRYPTO_dup_ex_data`. `CRYPTO_aligned_alloc_array` and `CRYPTO_clear_realloc_array` are discovered seam functions with no observed call site at this candidate.
- The enclosing `function` is a best-effort backwards scan for the nearest `fn` at lower indentation; trait declarations, macro bodies, and unusual layouts can misattribute a name.
- Seam presence remains a file-level token heuristic and is an upper bound on reconstruction, never a per-site proof.

## Non-claims

- This refresh measures ownership-reconstruction progress only; it claims no SAFETY_DISCHARGED and no SAFE_COMPATIBLE.
- The 33 historical DROP_IN_PASS verdicts are against an EARLIER candidate; functional re-testing is required before graduation.
- A present seam (OwnedCtx/OwnedBuf/impl Drop/…) is OWNERSHIP_RECONSTRUCTED, never discharge.
- Mechanism→file association is a declared directory mapping, not a per-symbol proof; it is an upper bound used for reachability.
- Production allocation calls are a work-burden metric, not a defect count; allocation and release calls are reported separately.
- Calls in files that also carry a seam token are classification burden, not proven defects or proven conversions.
