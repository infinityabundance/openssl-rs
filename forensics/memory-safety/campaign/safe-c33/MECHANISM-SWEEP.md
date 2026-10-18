# Mechanism sweep — cross-file candidates for the defects found in `evp/digest`, `evp/pkey_ctx`, `provider/cipher`, `evp/cipher_ctx`, `provider/kdf`, `evp/pkey`

**Status: candidate inventory, not a defect report.** Every row below is a pattern match that needs a source/authority check and a runtime or ownership witness. No candidate is confirmed as a defect by this document. `HIGH` means "most likely real if the stated reachability holds"; it is not a verification result.

- Repository: `/mnt/1tb_kingston/openssl-rs`
- Branch / HEAD at sweep time: `integrate/safe-c33` / `b15ef7aad`
- Method: `rg` + a brace-matching Python scan over `src/**/*.rs`; inline `#[cfg(test)]` module ranges were excluded where practical. No builds, tests, or runtime tools were run (read-only search subagent).
- Companion data: `forensics/memory-safety/campaign/safe-c33/atlas-refresh/mechanism-candidates.json`

## Per-class counts

| Class | HIGH | MEDIUM | LOW | Total |
|---|---:|---:|---:|---:|
| `1_self_aliasing_copy` | 8 | 5 | 68 | 81 |
| `2_publication_before_acquisition` | 0 | 5 | 15 | 20 |
| `3_shallow_owned_copy` | 0 | 0 | 0 | 0 |
| `4_safe_fn_raw_deref` | 0 | 6 | 46 | 52 |
| `5_destination_extent` | 2 | 1 | 0 | 3 |
| `6_secret_cleanse_gap` | 2 | 3 | 2 | 7 |
| `7_failure_path_release` | 0 | 1 | 3 | 4 |
| **Total** | **12** | **21** | **134** | **167** |

Class 3 has **zero** candidates: a scan of every `struct` in `src/` found 28 types with Rust owning members (`Vec`, `Box`, `String`, `CString`, `Owned*`, maps), and no `copy_nonoverlapping` / `*dst = *src` whole-struct copy names or casts any of them. The raw copies found are C-layout structs whose pointers are non-owning or are re-acquired explicitly.

## Top 20 candidates by severity

| # | Severity | Class | Location | Symbol | Operation / why it is ranked here |
|---:|---|---|---|---|---|
| 1 | **HIGH** | `1_self_aliasing_copy` | `src/provider/digest.rs:434` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx.cast::<u8>(), outctx.cast::<u8>(), size_of::<Ctx>()) over the whole provider digest context, inside a copyctx callback |
| 2 | **HIGH** | `1_self_aliasing_copy` | `src/provider/digest.rs:620` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx.cast::<u8>(), outctx.cast::<u8>(), size_of::<ShaCtx>()) over the whole provider digest context, inside a copyctx callback |
| 3 | **HIGH** | `1_self_aliasing_copy` | `src/provider/digest.rs:907` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx, outctx, size_of::<Md5Sha1Ctx>()) over the whole provider digest context, inside a copyctx callback |
| 4 | **HIGH** | `1_self_aliasing_copy` | `src/provider/digest.rs:1089` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx, outctx, size_of::<Md5Sha1Ctx>()) over the whole provider digest context, inside a copyctx callback |
| 5 | **HIGH** | `1_self_aliasing_copy` | `src/provider/digest.rs:1263` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx, outctx, size_of::<MdData>()) over the whole provider digest context, inside a copyctx callback |
| 6 | **HIGH** | `1_self_aliasing_copy` | `src/provider/digest.rs:1749` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx, outctx, size_of::<MdData>()) over the whole provider digest context, inside a copyctx callback (BLAKE2) |
| 7 | **HIGH** | `1_self_aliasing_copy` | `src/provider/legacyprov.rs:323` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx, outctx, size_of::<ctx>()) over the whole legacy-provider digest context, inside a copyctx callback |
| 8 | **HIGH** | `1_self_aliasing_copy` | `src/provider/legacyprov.rs:521` | `copyctx` | operation: ptr::copy_nonoverlapping(inctx, outctx, size_of::<Mdc2Ctx>()) over the whole legacy-provider digest context, inside a copyctx callback |
| 9 | **HIGH** | `5_destination_extent` | `src/provider/cipher_tdes_wrap.rs:377` | `tdes_wrap_cipher` | operation: if outsize < inl { return 0 |
| 10 | **HIGH** | `5_destination_extent` | `src/provider/cipher_tdes_wrap.rs:409` | `tdes_wrap_update` | operation: if outsize < inl { return 0 |
| 11 | **HIGH** | `6_secret_cleanse_gap` | `src/cmp/cmp_ctx.rs:479` | `ossl_cmp_ctx_free / cleanup` | operation: ptr::write_bytes((*(*ctx).secret_value).data, 0, len) before ASN1_OCTET_STRING_free. This is secret_value, and write_bytes is non-volatile, so the optimizer may remove the clearing (OPENSSL_cleanse uses volatile writes + fence). Evidence needed: confirm the authority uses OPENSSL_cleanse here and replace with runtime::mem::cleanse/OPENSSL_cleanse |
| 12 | **HIGH** | `6_secret_cleanse_gap` | `src/cmp/cmp_ctx.rs:1062` | `ossl_cmp_ctx_set0_secret_value` | operation: ptr::write_bytes((*(*ctx).secret_value).data, 0, l) before freeing/replacing secret_value |
| 13 | **MEDIUM** | `1_self_aliasing_copy` | `src/evp/cipher_ctx.rs:1095` | `EVP_CIPHER_CTX_copy` | operation: unsafe { ptr::copy_nonoverlapping(in_, out, 1) } |
| 14 | **MEDIUM** | `1_self_aliasing_copy` | `src/evp/encode.rs:295` | `EVP_ENCODE_CTX_copy` | operation: unsafe { ptr::copy_nonoverlapping(sctx, dctx, 1) } |
| 15 | **MEDIUM** | `1_self_aliasing_copy` | `src/evp/pkey_asn1.rs:665` | `EVP_PKEY_asn1_copy` | operation: unsafe { ptr::copy_nonoverlapping(src, dst, 1) } |
| 16 | **MEDIUM** | `1_self_aliasing_copy` | `src/mac/cmac.rs:314` | `CMAC_CTX_copy` | operation: ptr::copy_nonoverlapping((*in_).k1.as_ptr(), (*out).k1.as_mut_ptr(), bl as usize) |
| 17 | **MEDIUM** | `1_self_aliasing_copy` | `src/modes/ocb.rs:286` | `CRYPTO_ocb128_copy_ctx` | operation: ptr::copy_nonoverlapping(...) (multiline whole-region copy) |
| 18 | **MEDIUM** | `2_publication_before_acquisition` | `src/evp/asymcipher.rs:303` | `evp_asym_cipher_from_algorithm` | operation: (*p).prov = prov |
| 19 | **MEDIUM** | `2_publication_before_acquisition` | `src/evp/exchange.rs:351` | `evp_keyexch_new` | operation: (*exchange).prov = prov |
| 20 | **MEDIUM** | `2_publication_before_acquisition` | `src/evp/kem.rs:247` | `evp_kem_new` | operation: (*p).prov = prov |

## Class notes and evidence still required

### 1 — Self-aliasing copy (81: 8 HIGH / 5 MEDIUM / 68 LOW)

The strongest cross-file instance is the provider **digest `copyctx`** callbacks (`src/provider/digest.rs`, `src/provider/legacyprov.rs`). `EVP_MD_CTX_copy_ex(ctx, ctx)` deliberately invokes `copyctx(algctx, algctx)` for a provider method that publishes both `dupctx` and `copyctx` (`src/evp/digest.rs:2925-2930`, with an in-file test at `:6003` asserting the same-pointer call). The provider callback then runs `ptr::copy_nonoverlapping` over the same region, which violates its non-overlap requirement. The callbacks are documented as "distinct per the caller's contract"; that contract is contradicted by the caller. Evidence needed: run the self-copy against each digest row; Miri or ASan confirms the violation; then use `ptr::copy` or an identity guard.

The five MEDIUM rows are exported copy APIs with no identity short-circuit: `EVP_PKEY_asn1_copy`, `CMAC_CTX_copy`, `CRYPTO_ocb128_copy_ctx`, `EVP_ENCODE_CTX_copy`, `EVP_CIPHER_CTX_copy`. `EVP_PKEY_meth_copy` already has the correct `ptr::eq` guard (`src/evp/pkey_ctx.rs:2171`) and is the template. The 68 LOW rows are fresh-destination `dup`/`dupctx`/`meth_dup`/helper copies, where both sides cannot normally be the same pointer; they are retained for completeness and need a publication-path witness, not a code change.

### 2 — Publication before acquisition (20: 5 MEDIUM / 15 LOW)

The five MEDIUM rows are provider-method constructors that store `prov` and then ignore the result of `ossl_provider_up_ref`. Unlike the constant-1 `EVP_*_up_ref` helpers, `ossl_provider_up_ref` really can fail (a child provider whose parent reference is refused; `src/provider/mod.rs:1882-1906`). If it fails, the published field has no reference and the eventual `*_free` is unbalanced. Evidence needed: force `ossl_provider_up_ref_parent` failure and exercise the method free path. The LOW rows either use a constant-1 `up_ref` or store a pointer only after a checked call.

### 3 — Shallow owned copy (0)

See the zero-candidate explanation above. This class cannot be declared absent in general: a copy hidden behind a type alias, a `transmute`, or a cast to `u8` would not be caught by the struct-name scan. No such case was found in the reviewed copy sites.

### 4 — Safe fn, raw deref (52: 6 MEDIUM / 46 LOW)

Only **parameter-derived** dereferences are listed: a safe fn with a `*mut`/`*const` parameter that reads or writes through it. Six are `pub(crate)` (`ssl_set_version_bound`, `send_certificate_request`, `lib_ctx_write_lock`, `lib_ctx_read_lock`, `lib_ctx_unlock`, `ossl_namemap_empty`); the rest are module-private helpers. None is exported as safe C API. This scan does **not** enumerate safe methods that dereference raw `self`-field pointers; that requires a different field-flow analysis and is a known limitation of this sweep.

### 5 — Destination extent (3: 2 HIGH / 1 MEDIUM)

`tdes_wrap_cipher` and `tdes_wrap_update` keep the authority check `outsize < inl` but the encrypting helper writes `inl + 8 (IV) + 8 (ICV) = inl + 16`. This is the same defect class already corrected for AES wrap at `src/provider/cipher.rs:3928-3981` (D561): that fix adds an encrypt-only derived requirement. The TDES rows were not given the equivalent check. Evidence needed: guard-page/ASan call with `outsize == inl` on the encrypt path, plus an authority-behaviour comparison (the authority's check is also insufficient for encryption; the campaign records memory-safety improvements as deliberate divergences).

### 6 — Secret cleanse gap (7: 2 HIGH / 3 MEDIUM / 2 LOW)

`src/cmp/cmp_ctx.rs:479` and `:1062` clear `secret_value->data` with non-volatile `ptr::write_bytes`. The crate already has a volatile `cleanse` primitive with a compiler fence (`src/runtime/mem.rs:1004-1012`), and `OPENSSL_cleanse` is the authority primitive for this field. An optimiser may legally drop the store before the subsequent free. Evidence needed: confirm the authority call, replace with `OPENSSL_cleanse`, and add an optimised-build canary/negative control.

The HPKE failure-path rows release `shared_secret` with plain `CRYPTO_free` while the destructor uses `CRYPTO_clear_free`; the Argon2 rows do the same for `secret`/`salt` after a range refusal. These may be faithful transcripts of authority error arms, so the evidence required is the exact authority line. The two LOW rows are public metadata (PKCS#12 salt, EC-group seed).

### 7 — Failure-path release (4: 1 MEDIUM / 3 LOW)

This class could not be searched exhaustively without a dataflow pass. The heuristic looked for functions that acquire with `CRYPTO_malloc/zalloc/strdup/memdup`, `Owned*::new`, or `*_up_ref`, have multiple returns, and contain no release token. Most hits are false positives because the release is moved into `Drop`, `RawCtx`, or a caller-visible error object. The MEDIUM row (`pkey_ec_copy`) leaves earlier allocations in the destination when a later duplicate fails; whether that is a leak depends on the caller resetting `dst`, which was not established here. `tdes_wrap`-style extent and `copyctx`-style identity findings above are stronger and should be fixed first.

## Not searched reliably

- **Same-pointer reachability in C API callers.** Whether an exported `unsafe extern "C"` copy is ever called with `dst == src` cannot be proven statically; the report marks the ones whose own caller inside this crate does so and leaves exported APIs to a caller/ABI witness.
- **Field-based raw dereferences in safe methods.** The class-4 scan is parameter-based only. A safe method that dereferences an owning raw field is only safe if its constructor invariant is enforced; that needs a field-flow/owner audit, not a grep.
- **Failure-path release (class 7).** A grep cannot distinguish a release moved into `Drop` from a genuine leak. A dataflow or targeted allocator-failure harness is required before any row is called a defect.
- **Secret role vs name.** Class 6 classification used names and surrounding roles; the final decision needs the authority source for each free/cleanse arm.

## Explicit non-claim

**Every entry in this sweep is a candidate, not a confirmed defect.** Severity expresses the priority for investigation. No code was edited, built, or tested; no source/authority hash was re-derived; no Miri/ASan/refcount/instrumentation evidence exists for any row. A `HIGH` row still requires the stated witness (self-copy reachability for class 1, guard-page/ASan for class 5, optimised-build canary for class 6) before it can be reported as a real defect, and each confirmation still needs the §21 boundary proof before any `SAFETY_DISCHARGED` claim.

## Resolution addendum — 2026-10-18, `integrate/safe-c33` @ `3db95b793`

Authority read from `forensics/authorities/src/openssl-3.6.4/`.

### Class 1 MEDIUM (five exported copy APIs)

| Site | Authority | Self-copy disposition |
|---|---|---|
| `src/evp/cipher_ctx.rs:1095` | `evp_enc.c:1782-1809` | **Not permitted.** `EVP_CIPHER_CTX_reset(out)` memsets the object (provider arm) before `*out = *in`; `in->cipher` is then NULL and `in->cipher->dupctx` dereferences it. The entry now refuses `out == in` with 0, leaving the input untouched (AGENTS §17 UB elimination); `copying_a_context_onto_itself_is_refused`. |
| `src/mac/cmac.rs:314` | `cmac.c:93-109` | **Not permitted.** The nested `EVP_CIPHER_CTX_copy(out->cctx, in->cctx)` has the same NULL-dereference self-copy as above. `CMAC_CTX_copy` now refuses `out == in` with 0 before reading either context; `copy_refuses_the_identity_and_leaves_the_source_alone`. |
| `src/evp/encode.rs:295` | `encode.c:128-133` | **Permitted as identity** (`memcpy` of a whole object, constant 1 answer). Identity guard added; `encode_ctx_copy_accepts_the_identity`. |
| `src/evp/pkey_asn1.rs:665` | `ameth_lib.c:255-272` | **Permitted as identity** (`*dst = *src` is defined when equal; five restores make it a no-op). Identity guard added; `asn1_copy_accepts_the_identity`. |
| `src/modes/ocb.rs:286` | `ocb128.c:194-208` | **Permitted as identity** for the header/`memcpy`, but the authority then allocates a second L-table and leaks the original. Guard added, preserving the `keyenc`/`keydec` overrides and skipping the leak; `ocb_copy_ctx_accepts_the_identity`. |

### Class 7 MEDIUM (`pkey_ec_copy`)

`ec_pmeth.c:60-90` acquires `dctx`, `gen_group`, `co_key` and `kdf_ukm` into
`dst->data` and returns 0 without releasing earlier acquisitions.
`EVP_PKEY_CTX_dup` (`pmeth_lib.c:608-610`) clears `rctx->pmeth` before
`EVP_PKEY_CTX_free`, so the method cleanup is never called and the partial state
leaks. Fixed by calling `pkey_ec_cleanup(dst)` on each failure return; executed
witness `copy_failure_releases_the_partially_built_destination`. This is a
recorded divergence (the authority leaks) and not a compatibility change to the
success path.

### Still open

No Miri/ASan run is claimed for the identity guards; the tests are functional
and refcount witnesses only. The class-5 TDES extent rows and class-6 cleanse
rows were not touched by this addendum.

