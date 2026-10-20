# Unsafe-site boundary attribution — safe-c33

**Attribution is NOT discharge.** A site placed under a boundary is covered by that boundary's declared scope only. Nothing here proves a caller contract, aliasing, lifetime, initialisation or cryptographic property, and no subsystem or consumer graduates by this record. `UNATTRIBUTED` is an explicit queue: it is neither a safety claim nor a defect claim.

Source: `forensics/memory-safety/campaign/safe-c33/atlas-refresh/unsafe-census.json` bound to candidate `c09eef8b94ce068c92557d9940decf50e8413c8c` with `src/` content hash `dadc34c4f1da59e05b25b0076123b0d7715784a92c41903d15a6730ba7154a6a`. Line context is read from that pinned commit, never from the working tree.

## Totals

| metric | value |
|---|---:|
| production unsafe sites (census) | 64,722 |
| attributed sites | 10,983 |
| **unattributed sites** | **53,739** |
| files total | 868 |
| files ZERO_UNSAFE (no production site) | 92 |
| files BOUNDARY_COVERED | 15 |
| files PARTIAL | 761 |
| post-census files classified (delta) | 9 |
| current source files at HEAD `1ae550590` | 877 |
| **unaccounted files at current HEAD** | **0** |
| **unattributed files** | **761** |
| worklist rows | 1,357 |
| worklist rows joined to a production site | 275 |
| worklist rows with no production unsafe site | 1,082 |

Boundary counts are exclusive: the first matching predicate in the fixed precedence list wins, so a site is counted once.

The census counts remain bound to `c09eef8b`. The nine post-census files are
classified separately in `atlas-refresh/post-census-delta.json`: 6 test-only
models/probes and 3 `PARTIAL` production helpers. The combined current-tree
partition is 92 `ZERO_UNSAFE` + 15 `BOUNDARY_COVERED` + 764 `PARTIAL` + 6
test-only = 877 files, 0 unaccounted.

## Sites by boundary

| boundary | sites | coverage | evidence |
|---|---:|---|---|
| `B-ALLOC-SEAM` | 281 | per-site (line-exact call-site evidence) | `atlas-refresh/site-worklist.json`, `OWNER-DUPLICATES.md`, `REFCOUNT-BOUNDARY.md` |
| `B-REFCOUNT` | 138 | per-site within a declared mechanism scope | `REFCOUNT-BOUNDARY.md` |
| `B-LOCK` | 2,244 | per-site within a declared mechanism scope | `OPAQUE-REPRESENTATIONS.md (subphase 44)` |
| `B-DESTRUCTOR` | 615 | per-site, trait-scoped | `DESTRUCTOR-CONTRACTS.md` |
| `B-OWNER-ADOPT` | 44 | per-site, constructor-scoped | `OWNER-DUPLICATES.md (canonical shared types)` |
| `B-OPAQUE` | 182 | file-level (representation boundary) | `OPAQUE-REPRESENTATIONS.md` |
| `B-FFI-ABI` | 7,479 | coverage-by-policy (not per-site proof) | `AGENTS.md §0/§10 (C ABI facade policy)` |
| **UNATTRIBUTED** | **53,739** | **explicit queue — no boundary registered** | — |

## Production and unattributed sites by kind

| kind | production | unattributed |
|---|---:|---:|
| `EXTERN_C_FN_DEF` | 836 | 0 |
| `HIGH_RISK_CALL` | 280 | 253 |
| `NONALLOC_FFI_CALL` | 7,548 | 0 |
| `UNSAFE_BLOCK` | 42,500 | 40,666 |
| `UNSAFE_EXTERN_BLOCK` | 10 | 9 |
| `UNSAFE_FN_DEF` | 13,206 | 12,669 |
| `UNSAFE_IMPL` | 332 | 132 |
| `UNSAFE_TRAIT` | 10 | 10 |

## 40 files with the most unattributed sites

| file | production | attributed | unattributed | main unattributed kinds |
|---|---:|---:|---:|---|
| `src/ssl/ssl_lib.rs` | 1,273 | 148 | 1,125 | UNSAFE_BLOCK=702, UNSAFE_FN_DEF=406, HIGH_RISK_CALL=16, UNSAFE_TRAIT=1 |
| `src/evp/pkey_ctx.rs` | 1,024 | 47 | 977 | UNSAFE_BLOCK=754, UNSAFE_FN_DEF=222, UNSAFE_IMPL=1 |
| `src/provider/cipher.rs` | 1,098 | 273 | 825 | UNSAFE_FN_DEF=414, UNSAFE_BLOCK=398, HIGH_RISK_CALL=11, UNSAFE_IMPL=1, UNSAFE_TRAIT=1 |
| `src/evp/digest.rs` | 711 | 19 | 692 | UNSAFE_BLOCK=570, UNSAFE_FN_DEF=120, HIGH_RISK_CALL=1, UNSAFE_IMPL=1 |
| `src/evp/cipher_ctx.rs` | 672 | 20 | 652 | UNSAFE_BLOCK=570, UNSAFE_FN_DEF=82 |
| `src/provider/kdf.rs` | 716 | 198 | 518 | UNSAFE_BLOCK=267, UNSAFE_FN_DEF=250, UNSAFE_TRAIT=1 |
| `src/evp/pkey.rs` | 568 | 84 | 484 | UNSAFE_BLOCK=378, UNSAFE_FN_DEF=106 |
| `src/cms/cms_env.rs` | 549 | 70 | 479 | UNSAFE_BLOCK=429, UNSAFE_FN_DEF=50 |
| `src/x509/v3_addr.rs` | 498 | 93 | 405 | UNSAFE_BLOCK=359, UNSAFE_FN_DEF=46 |
| `src/hpke/mod.rs` | 416 | 12 | 404 | UNSAFE_BLOCK=366, UNSAFE_FN_DEF=37, HIGH_RISK_CALL=1 |
| `src/params/mod.rs` | 395 | 3 | 392 | UNSAFE_BLOCK=312, UNSAFE_FN_DEF=79, UNSAFE_IMPL=1 |
| `src/pkcs7/pk7_doit.rs` | 431 | 48 | 383 | UNSAFE_BLOCK=350, UNSAFE_FN_DEF=33 |
| `src/x509/v3_utl.rs` | 424 | 43 | 381 | UNSAFE_BLOCK=322, UNSAFE_FN_DEF=59 |
| `src/cmp/cmp_msg.rs` | 472 | 100 | 372 | UNSAFE_BLOCK=324, UNSAFE_FN_DEF=48 |
| `src/pem/pvkfmt.rs` | 382 | 26 | 356 | UNSAFE_BLOCK=318, UNSAFE_FN_DEF=38 |
| `src/ssl/t1_trce.rs` | 353 | 0 | 353 | UNSAFE_BLOCK=327, UNSAFE_FN_DEF=25, UNSAFE_IMPL=1 |
| `src/cms/cms_sd.rs` | 422 | 73 | 349 | UNSAFE_BLOCK=307, UNSAFE_FN_DEF=40, HIGH_RISK_CALL=2 |
| `src/x509/x509_vfy.rs` | 467 | 121 | 346 | UNSAFE_BLOCK=219, UNSAFE_FN_DEF=127 |
| `src/evp/bio_enc.rs` | 340 | 9 | 331 | UNSAFE_BLOCK=301, UNSAFE_FN_DEF=30 |
| `src/cmp/cmp_asn.rs` | 356 | 40 | 316 | UNSAFE_BLOCK=237, UNSAFE_FN_DEF=78, UNSAFE_IMPL=1 |
| `src/store/store_lib.rs` | 340 | 31 | 309 | UNSAFE_BLOCK=257, UNSAFE_FN_DEF=52 |
| `src/ts/ts_rsp_sign.rs` | 329 | 23 | 306 | UNSAFE_BLOCK=264, UNSAFE_FN_DEF=42 |
| `src/x509/x_pubkey.rs` | 315 | 21 | 294 | UNSAFE_BLOCK=240, UNSAFE_FN_DEF=53, UNSAFE_IMPL=1 |
| `src/cms/cms_smime.rs` | 332 | 44 | 288 | UNSAFE_BLOCK=252, UNSAFE_FN_DEF=36 |
| `src/crmf/crmf_lib.rs` | 299 | 21 | 278 | UNSAFE_BLOCK=227, UNSAFE_FN_DEF=51 |
| `src/x509/v3_asid.rs` | 324 | 46 | 278 | UNSAFE_BLOCK=247, UNSAFE_FN_DEF=31 |
| `src/asn1/asn_mime.rs` | 329 | 52 | 277 | UNSAFE_BLOCK=247, UNSAFE_FN_DEF=30 |
| `src/rsa/pmeth.rs` | 283 | 7 | 276 | UNSAFE_BLOCK=253, UNSAFE_FN_DEF=21, HIGH_RISK_CALL=2 |
| `src/provider/encode_key2any.rs` | 299 | 25 | 274 | UNSAFE_BLOCK=218, UNSAFE_FN_DEF=55, UNSAFE_EXTERN_BLOCK=1 |
| `src/cmp/cmp_client.rs` | 343 | 71 | 272 | UNSAFE_BLOCK=253, UNSAFE_FN_DEF=19 |
| `src/asn1/d2i.rs` | 272 | 10 | 262 | UNSAFE_BLOCK=241, UNSAFE_FN_DEF=21 |
| `src/ssl/statem/statem_srvr.rs` | 342 | 80 | 262 | UNSAFE_BLOCK=214, UNSAFE_FN_DEF=46, HIGH_RISK_CALL=1, UNSAFE_TRAIT=1 |
| `src/cmp/cmp_vfy.rs` | 314 | 62 | 252 | UNSAFE_BLOCK=232, UNSAFE_FN_DEF=20 |
| `src/runtime/conf/def.rs` | 278 | 30 | 248 | UNSAFE_BLOCK=210, UNSAFE_FN_DEF=37, UNSAFE_IMPL=1 |
| `src/x509/x_all.rs` | 256 | 9 | 247 | UNSAFE_BLOCK=147, UNSAFE_FN_DEF=98, HIGH_RISK_CALL=2 |
| `src/asn1/prim.rs` | 253 | 7 | 246 | UNSAFE_BLOCK=186, UNSAFE_FN_DEF=60 |
| `src/x509/x509_lu.rs` | 338 | 92 | 246 | UNSAFE_BLOCK=166, UNSAFE_FN_DEF=80 |
| `src/evp/signature.rs` | 253 | 12 | 241 | UNSAFE_BLOCK=200, UNSAFE_FN_DEF=41 |
| `src/x509/v3_crld.rs` | 278 | 37 | 241 | UNSAFE_BLOCK=202, UNSAFE_FN_DEF=38, UNSAFE_IMPL=1 |
| `src/cmp/cmp_server.rs` | 277 | 40 | 237 | UNSAFE_BLOCK=212, UNSAFE_FN_DEF=24, HIGH_RISK_CALL=1 |

## Boundary predicates

### `B-ALLOC-SEAM`

Production allocation/release call sites listed in atlas-refresh/site-worklist.json.  The join is exact on (file, line); each matched census operation on that line is attributed.

Predicate: `(file, line) appears in site-worklist.json`

### `B-REFCOUNT`

Sites in src/runtime/refcount.rs and remaining sites whose enclosing function or immediate source window references up_ref/down_ref.  Evaluated after B-ALLOC-SEAM.

Predicate: `file == src/runtime/refcount.rs OR \b(down_ref|up_ref)\s*\( in the enclosing fn / line window`

### `B-LOCK`

Sites in src/runtime/thread.rs and remaining sites whose enclosing function or immediate source window references CRYPTO_THREAD_*.  Evaluated after B-ALLOC-SEAM and B-REFCOUNT.

Predicate: `file == src/runtime/thread.rs OR \bCRYPTO_THREAD_ in the enclosing fn / line window`

### `B-DESTRUCTOR`

unsafe impls of the destructor traits enumerated in DESTRUCTOR-CONTRACTS.md (CtxDestroy, CipherDestroy, KdfDestroy, MacDestroy, DrbgCtx, GcmDestroy, FreeOnDrop, Drop) and definitions of *_destroy_body.  Send/Sync and other unsafe impls are deliberately not attributed here.

Predicate: `kind == UNSAFE_IMPL and impl trait in DESTRUCTOR_TRAITS, OR enclosing fn name ends with destroy_body`

### `B-OWNER-ADOPT`

unsafe adopt/from_raw/RawCtx/assume_init/into_raw sites whose enclosing constructor is associated with one of the shared owner types OwnedBuf, OwnedStr, OwnedCtx, RawCtx or OwnedBlock.  Local owner types with other names are left unattributed.

Predicate: `enclosing fn name in OWNER_CTOR_NAMES AND impl header/function mentions a shared owner type AND an adopt-ish token is present`

### `B-OPAQUE`

Remaining sites in the opaque-representation files named in OPAQUE-REPRESENTATIONS.md: src/runtime/thread.rs, src/runtime/stack.rs, src/runtime/lhash.rs, src/bn/recp.rs.  Sites already claimed by an earlier boundary keep that boundary; this is file-level representation coverage, not a per-site proof.

Predicate: `file in OPAQUE_FILES`

### `B-FFI-ABI`

Every EXTERN_C_FN_DEF and every non-allocator CRYPTO_* / OPENSSL_* / ossl_* call recorded by the census that is not already claimed by an earlier, more specific boundary.  This is residual coverage-by-policy at the ABI edge, not a per-site ABI proof; allocator calls are covered by B-ALLOC-SEAM instead.

Predicate: `kind in {EXTERN_C_FN_DEF, NONALLOC_FFI_CALL}`

## Residual limitations

- The census is lexical, not a Rust parser: macro-generated operations are counted only where the macro token appears in source, and no expansion-site attribution is possible.
- Generic and trait-level obligations (for example an `unsafe trait` definition or a generic impl) are not per-site proofs; `UNSAFE_TRAIT` and Send/Sync `unsafe impl` sites are deliberately left unattributed because no boundary in this registry owns those obligations.
- One source site can serve more than one obligation. The output assigns exactly one boundary by precedence so counts reconcile; that is a reporting choice, not a claim that the other obligations vanish.
- `B-ALLOC-SEAM` is a line-exact join with the worklist. A multi-line call whose operation is recorded on a different line is not joined. Most worklist rows are safe allocation/release calls with no production unsafe operation on the same line; those rows are reported as `worklist_rows_without_production_site`.
- `B-FFI-ABI` is coverage-by-policy at the ABI edge, not a per-site ABI or callback proof. It does not discharge a reentrancy or ABI obligation.
- `B-OPAQUE` is file-level representation coverage, not a per-site proof of the opaque-representation contract.
- The attribution is bound to the census candidate commit, which may differ from the current source HEAD. It does not describe uncommitted or later source without regenerating the census.

## Reconciliation

| check | result |
|---|---|
| census production sites | 64,722 |
| recomputed production sites | 64,722 |
| attributed + unattributed | 64,722 |
| per-file production/test/seam counts | match |
| per-kind production totals | match |
| source content hash vs census | match |

## Post-census delta (877-file reconciliation, 2026-10-20)

The census above is pinned to `c09eef8b` (868 files). Nine `src/**/*.rs` files
exist at HEAD `1ae550590` that did not exist in that commit. They are classified
in `atlas-refresh/post-census-delta.json`, produced with the same
`unsafe_census.py` scanner and `unsafe_attribution.py` boundary predicates.

| file | class | production sites | boundary / receipt |
|---|---|---:|---|
| `src/runtime/bio/owned_ctx_model.rs` | TEST_ONLY | 0 (7 test-only ops) | `cfg(test)` `#[path]`; OB-3 model |
| `src/runtime/bio/zero_state.rs` | TEST_ONLY | 0 (2) | `cfg(test)`; OB-3 zero-state sweep |
| `src/runtime/member_slot_model.rs` | TEST_ONLY | 0 (8) | `cfg(test)`; OB-4b model |
| `src/runtime/owned_buf_model.rs` | TEST_ONLY | 0 (12) | `cfg(test)` `#[path]`; OB-1 model |
| `src/runtime/owned_str_model.rs` | TEST_ONLY | 0 (7) | `cfg(test)` `#[path]`; OB-2 model |
| `src/runtime/release_probe.rs` | TEST_ONLY | 0 (0) | `cfg(test)`; release-arm probes |
| `src/runtime/foreign.rs` | PARTIAL | 19 | `B-DESTRUCTOR` / `B-OWNER-ADOPT`; `DESTRUCTOR-CONTRACTS.md`, `OWNER-DUPLICATES.md` section 5, subphase 89 |
| `src/runtime/mem_coords.rs` | PARTIAL | 1 | `B-ALLOC-SEAM`; subphase 70 |
| `src/runtime/member_slot.rs` | PARTIAL | 4 | OB-4 member-buffer boundary; `MEMBER-BUFFER-MODEL.md`, subphase 89 |

Combined partition at HEAD `1ae550590`: **92** `ZERO_UNSAFE` + **15**
`BOUNDARY_COVERED` + **764** `PARTIAL` + **6** test-only = **877**; unaccounted
**0**.

The six test-only files are `cfg(test)`-only models/probes and are not
production audit surface. The three production helpers remain `PARTIAL`, not
`BOUNDARY_COVERED`: the census boundary registry has no predicate for an
`unsafe trait` declaration, for `OwnedCtx::new`, or for the OB-4 member-slot
proof boundaries. Their sites carry explicit `# Safety` contracts in the shared
boundary receipts, but this table is classification, not a per-site discharge.

This delta does not re-pin the census and does not invalidate the 761 per-file
audit records bound to `c09eef8b`.
