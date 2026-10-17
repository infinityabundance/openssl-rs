# Unsafe census — src/**/*.rs

Deterministic, candidate-bound measurement of unsafe operations. This report makes no safety or compatibility claim.

- Schema: `openssl-rs/atlas/unsafe-census/v2`
- Generator: `forensics/memory-safety/campaign/safe-c33/unsafe_census.py`
- Generated (candidate-bound): `2026-10-17T20:31:17Z`
- Branch: `integrate/safe-c33`
- HEAD: `8751ea75f742c90c19b92564257566f71d606dcd`
- Crate version: `0.0.27`
- Rust files: 868
- Source content sha256: `c06aea132e05ccb47651b3a668927db713e1391b53e50d1c7de9b4f1574ec653`

## Compact JSON schema

The JSON is minified (no indentation) and uses schema v2. `kind_codes` maps each operation kind to the code used in site arrays.
`files[].sites` records are three-element arrays (`line`, `kind_code`, `function`); the third field is the enclosing function name.
`kind_codes` maps: `EXTERN_C_FN_DEF`=`EC`, `HIGH_RISK_CALL`=`HR`, `NONALLOC_FFI_CALL`=`FC`, `UNSAFE_BLOCK`=`UB`, `UNSAFE_EXTERN_BLOCK`=`UE`, `UNSAFE_FN_DEF`=`UF`, `UNSAFE_IMPL`=`UI`, `UNSAFE_TRAIT`=`UT`.
Per-file aggregates remain in `files[].kind_counts`, `files[].partition_counts`, and the scalar count fields; `RAW_POINTER_TYPE` remains a per-file context scalar, not a site.

## Existing Phase-25 census

- Path: `artifacts/phase25/source-census.json`
- Schema: `openssl-rs/atlas/phase25-source-census/v1`
- Generator: `forensics/tools/ms_census.py`
- Candidate commit: `f0789077aa1982fdb94141ce9a74f45195de60d3`
- Candidate matches current HEAD: `False`
- Reused for the per-file denominator: `False`
- Reason: schema and count categories consulted; not reused because the artifact is bound to a different source candidate and does not provide this production/test/seam lexical partition
- Lexical cross-check from the artifact: unsafe_blocks=44,574, unsafe_fns=4,138, unsafe_impls=135, unsafe_externs=9,998, extern_c_fns=10,869.

## Totals by kind

| kind | production | test-only | allocator seam | total |
|---|---:|---:|---:|---:|
| `UNSAFE_BLOCK` | 42,533 | 2,241 | 93 | 44,867 |
| `UNSAFE_FN_DEF` | 13,263 | 169 | 33 | 13,465 |
| `UNSAFE_IMPL` | 331 | 3 | 0 | 334 |
| `UNSAFE_TRAIT` | 29 | 0 | 0 | 29 |
| `UNSAFE_EXTERN_BLOCK` | 10 | 0 | 0 | 10 |
| `HIGH_RISK_CALL` | 274 | 40 | 1 | 315 |
| `EXTERN_C_FN_DEF` | 836 | 6 | 10 | 852 |
| `NONALLOC_FFI_CALL` | 7,548 | 1,797 | 48 | 9,393 |
| **operations** | **64,824** | **4,256** | **185** | **69,265** |

### Separate context metric (not an unsafe operation)

Raw-pointer type contexts (`*mut` / `*const`): **47,090** (production 45,858, test-only 1,041, allocator seam 191).

Extern "C" function definitions: **9,805** total; 8,953 are `unsafe extern "C" fn` and are counted once under `UNSAFE_FN_DEF`, leaving 852 safe-ABI `EXTERN_C_FN_DEF` sites.

## Top 25 production files

| file | production ops | breakdown |
|---|---:|---|
| `src/ssl/ssl_lib.rs` | 1,273 | UNSAFE_BLOCK=797, UNSAFE_FN_DEF=422, UNSAFE_IMPL=4, UNSAFE_TRAIT=1, HIGH_RISK_CALL=18, NONALLOC_FFI_CALL=99 |
| `src/provider/cipher.rs` | 1,098 | UNSAFE_BLOCK=442, UNSAFE_FN_DEF=445, UNSAFE_IMPL=28, UNSAFE_TRAIT=1, HIGH_RISK_CALL=11, NONALLOC_FFI_CALL=199 |
| `src/evp/pkey_ctx.rs` | 1,026 | UNSAFE_BLOCK=776, UNSAFE_FN_DEF=225, UNSAFE_IMPL=3, NONALLOC_FFI_CALL=34 |
| `src/provider/kdf.rs` | 716 | UNSAFE_BLOCK=286, UNSAFE_FN_DEF=267, UNSAFE_IMPL=14, UNSAFE_TRAIT=1, NONALLOC_FFI_CALL=153 |
| `src/evp/digest.rs` | 713 | UNSAFE_BLOCK=595, UNSAFE_FN_DEF=125, UNSAFE_IMPL=3, HIGH_RISK_CALL=1, EXTERN_C_FN_DEF=2, NONALLOC_FFI_CALL=20 |
| `src/evp/cipher_ctx.rs` | 672 | UNSAFE_BLOCK=583, UNSAFE_FN_DEF=83, UNSAFE_IMPL=1, EXTERN_C_FN_DEF=1, NONALLOC_FFI_CALL=13 |
| `src/evp/pkey.rs` | 572 | UNSAFE_BLOCK=440, UNSAFE_FN_DEF=112, UNSAFE_IMPL=1, UNSAFE_TRAIT=1, NONALLOC_FFI_CALL=34 |
| `src/cms/cms_env.rs` | 549 | UNSAFE_BLOCK=429, UNSAFE_FN_DEF=50, NONALLOC_FFI_CALL=70 |
| `src/x509/v3_addr.rs` | 498 | UNSAFE_BLOCK=360, UNSAFE_FN_DEF=47, EXTERN_C_FN_DEF=9, NONALLOC_FFI_CALL=82 |
| `src/cmp/cmp_msg.rs` | 472 | UNSAFE_BLOCK=324, UNSAFE_FN_DEF=48, NONALLOC_FFI_CALL=100 |
| `src/x509/x509_vfy.rs` | 469 | UNSAFE_BLOCK=223, UNSAFE_FN_DEF=130, UNSAFE_IMPL=1, EXTERN_C_FN_DEF=1, NONALLOC_FFI_CALL=116 |
| `src/pkcs7/pk7_doit.rs` | 431 | UNSAFE_BLOCK=350, UNSAFE_FN_DEF=33, NONALLOC_FFI_CALL=48 |
| `src/x509/v3_utl.rs` | 428 | UNSAFE_BLOCK=332, UNSAFE_FN_DEF=63, UNSAFE_IMPL=1, UNSAFE_TRAIT=1, NONALLOC_FFI_CALL=42 |
| `src/cms/cms_sd.rs` | 422 | UNSAFE_BLOCK=307, UNSAFE_FN_DEF=40, HIGH_RISK_CALL=2, NONALLOC_FFI_CALL=73 |
| `src/hpke/mod.rs` | 415 | UNSAFE_BLOCK=379, UNSAFE_FN_DEF=38, HIGH_RISK_CALL=1, EXTERN_C_FN_DEF=4, NONALLOC_FFI_CALL=4 |
| `src/params/mod.rs` | 395 | UNSAFE_BLOCK=312, UNSAFE_FN_DEF=79, UNSAFE_IMPL=1, EXTERN_C_FN_DEF=1, NONALLOC_FFI_CALL=2 |
| `src/rand/rand_lib.rs` | 388 | UNSAFE_BLOCK=250, UNSAFE_FN_DEF=48, UNSAFE_IMPL=2, UNSAFE_TRAIT=1, EXTERN_C_FN_DEF=5, NONALLOC_FFI_CALL=82 |
| `src/pem/pvkfmt.rs` | 382 | UNSAFE_BLOCK=318, UNSAFE_FN_DEF=39, NONALLOC_FFI_CALL=25 |
| `src/x509/v3_purp.rs` | 363 | UNSAFE_BLOCK=271, UNSAFE_FN_DEF=59, UNSAFE_IMPL=2, UNSAFE_TRAIT=1, NONALLOC_FFI_CALL=30 |
| `src/cmp/cmp_asn.rs` | 356 | UNSAFE_BLOCK=237, UNSAFE_FN_DEF=78, UNSAFE_IMPL=1, EXTERN_C_FN_DEF=9, NONALLOC_FFI_CALL=31 |
| `src/provider/rand.rs` | 356 | UNSAFE_BLOCK=117, UNSAFE_FN_DEF=122, UNSAFE_IMPL=5, UNSAFE_TRAIT=1, NONALLOC_FFI_CALL=111 |
| `src/ssl/t1_trce.rs` | 353 | UNSAFE_BLOCK=327, UNSAFE_FN_DEF=25, UNSAFE_IMPL=1 |
| `src/cmp/cmp_client.rs` | 343 | UNSAFE_BLOCK=253, UNSAFE_FN_DEF=19, NONALLOC_FFI_CALL=71 |
| `src/ssl/statem/statem_srvr.rs` | 342 | UNSAFE_BLOCK=220, UNSAFE_FN_DEF=46, UNSAFE_IMPL=4, UNSAFE_TRAIT=1, HIGH_RISK_CALL=1, NONALLOC_FFI_CALL=76 |
| `src/store/store_lib.rs` | 342 | UNSAFE_BLOCK=264, UNSAFE_FN_DEF=56, UNSAFE_IMPL=3, NONALLOC_FFI_CALL=23 |

## Closure files with ZERO production unsafe ops

Closure set: 628 files (union of the nine Safe-33 mechanism path sets).

- Zero production operations (all counted kinds, including extern "C" definitions and non-allocator FFI calls): **38**
- Zero production unsafe-language constructs or high-risk calls (narrower subset): **36**

- `src/asn1/items.rs`
- `src/asn1/mod.rs`
- `src/bn/dh_data.rs`
- `src/bn/limbs.rs`
- `src/bn/mod.rs`
- `src/bn/prime_data.rs`
- `src/cmp/mod.rs`
- `src/cms/mod.rs`
- `src/crmf/mod.rs`
- `src/ec/curve25519_data.rs`
- `src/ec/curve448_tables.rs`
- `src/ec/curve_data.rs`
- `src/evp/mod.rs`
- `src/ffc/mod.rs`
- `src/ocsp/mod.rs`
- `src/pem/mod.rs`
- `src/pkcs12/mod.rs`
- `src/pkcs7/mod.rs`
- `src/property/mod.rs`
- `src/provider/asymcipher.rs`
- `src/provider/kem.rs`
- `src/provider/signature.rs`
- `src/rand/mod.rs`
- `src/runtime/err_reasons.rs`
- `src/runtime/err_sites.rs`
- `src/runtime/err_strings.rs`
- `src/runtime/mem.rs`
- `src/runtime/obj_table.rs`
- `src/runtime/secure.rs`
- `src/ssl/adv_alloc.rs`
- `src/ssl/mod.rs`
- `src/ssl/quic/mod.rs`
- `src/ssl/record/mod.rs`
- `src/ssl/rio/mod.rs`
- `src/ssl/ssl_ciph_table.rs`
- `src/ssl/statem/mod.rs`
- `src/store/mod.rs`
- `src/x509/mod.rs`

## Method

- Partition: production = not in a #[cfg(test)] module/item and not an allocator-seam file; test_only = in a #[cfg(test)] inline module/item or a file pulled in by #[cfg(test)] mod name; allocator_seam = src/runtime/mem.rs or src/runtime/secure.rs. The partition order is seam, then test, then production.
- Stripping: atlas_refresh.strip_comments_and_literals; offsets and 1-based line numbers are preserved. The ABI string literal immediately after `extern` is restored so `extern "C"` remains visible; comments and every other literal stay stripped.
- Enclosing function: atlas_refresh._enclosing_fn: nearest preceding fn at lower indentation (best effort)
- Closure zero-production lists can include allocator-seam files (`src/runtime/mem.rs`, `src/runtime/secure.rs`): their operations are classified as allocator seam, so their production count is zero by the partition, not because the file is unsafe-free.
- Allocator surface: 18 alloc and 6 release names discovered from `src/runtime/mem.rs`, `src/runtime/secure.rs`; those calls are excluded from `NONALLOC_FFI_CALL`.
- `RAW_POINTER_TYPE` is a context metric and is excluded from every operation total.

## Independent reconciliation

Run `python3 forensics/memory-safety/campaign/safe-c33/unsafe_census.py --check` for an independent `grep -E` pass over a temporary tree of stripped sources.  It compares per-file counts for the unsafe constructs, extern "C" definitions, high-risk calls, non-allocator FFI calls, and raw-pointer contexts; any mismatch exits non-zero.

## Residual limitations

- Lexical scanner, not a Rust parser: macro bodies are counted where written; tokens produced only by macro expansion are not observed.
- Enclosing function is a best-effort nearest-indent heuristic; closures, nested items, and macro-generated functions can be misattributed.
- Test classification follows `atlas_refresh`: `#[cfg(test)]` inline modules/items and resolvable `#[cfg(test)] mod name;` files only. `#[path]` overrides, `cfg_attr(..., cfg(test))`, and `cfg(any(test, ...))` are not reclassified.
- `EXTERN_C_FN_DEF` counts named per-item `extern "C" fn` definitions; function-pointer types such as `extern "C" fn(...)` and bare `fn` declarations inside `extern "C" { ... }` blocks are not separate definition sites (the enclosing unsafe extern block is counted).
- `NONALLOC_FFI_CALL` is lexical and prefix-based; calls through function pointers, type aliases, or macros are not observed. The allocator exclusion set is derived from the seam files, not from C headers.
- `RAW_POINTER_TYPE` counts `*mut` / `*const` type-syntax occurrences, not distinct declarations or pointer values.
- Counts are a denominator, not a severity ranking. They say nothing about reachability, ownership soundness, compatibility, or cryptographic correctness.
